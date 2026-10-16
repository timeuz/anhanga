from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from anhanga.engine.models import ProbeResult
from anhanga.engine.probe import (
    ALLOWED_SCHEMES,
    InstrumentedPinnedNetworkBackend,
    SSRFBlockedError,
    _create_instrumented_transport,
    resolve_and_validate_host,
)

WebhookProvider = Literal["slack", "teams", "telegram"]


def detect_webhook_provider(
    webhook_url: str, provider: str = "auto"
) -> WebhookProvider:
    """Detecta automaticamente o provedor de webhook pela URL ou usa o explícito."""
    norm = (provider or "auto").strip().lower()
    if norm in ("slack", "teams", "telegram"):
        return norm  # type: ignore[return-value]

    lower_url = (webhook_url or "").lower()
    if "api.telegram.org" in lower_url or "telegram" in lower_url:
        return "telegram"
    if any(
        domain in lower_url
        for domain in (
            "webhook.office.com",
            "office.com",
            "outlook.com",
            "logic.azure.com",
            "teams.microsoft.com",
            "teams",
        )
    ):
        return "teams"
    return "slack"


def _format_tls_status(result: ProbeResult) -> str:
    if result.tls is None:
        return "N/A (HTTP sem TLS)"
    if not result.tls.valid:
        return "INVÁLIDO / EXPIRADO"
    days = (
        f"{result.tls.days_remaining}d restantes"
        if result.tls.days_remaining is not None
        else "válido"
    )
    proto = result.tls.protocol or "TLS"
    warn = " [EXPIRANDO]" if result.tls.alert_expiring else ""
    return f"Válido ({proto}, {days}){warn}"


def _collect_violations(
    result: ProbeResult, violations: list[str] | None = None
) -> list[str]:
    items = list(violations) if violations else []
    if not result.is_up and not any("offline" in v.lower() or "down" in v.lower() for v in items):
        reason = result.error or f"HTTP {result.status_code or 'ERR'}"
        items.insert(0, f"Alvo OFFLINE: {reason}")
    if result.tls and result.tls.alert_expiring:
        msg = f"Certificado TLS expirando em {result.tls.days_remaining} dias"
        if msg not in items:
            items.append(msg)
    return items


def build_slack_payload(
    result: ProbeResult, violations: list[str] | None = None
) -> dict[str, Any]:
    """Constrói payload Slack (Block Kit + Attachments coloridos)."""
    all_violations = _collect_violations(result, violations)
    if not result.is_up:
        color = "#ef4444"
        status_label = f"🔴 OFFLINE ({result.status_code or 'ERR'})"
    elif all_violations:
        color = "#f59e0b"
        status_label = f"🟡 ALERTA SLO/SEC (HTTP {result.status_code})"
    else:
        color = "#10b981"
        status_label = f"🟢 ONLINE (HTTP {result.status_code})"

    tls_status = _format_tls_status(result)
    p95_ms = (
        result.sampling.p95_ms
        if (result.sampling and result.sampling.p95_ms > 0)
        else result.timings.total_ms
    )
    summary_text = (
        f"[Anhangá] {status_label} — {result.target_url} | "
        f"Total: {result.timings.total_ms:.2f}ms | TTFB: {result.timings.ttfb_ms:.2f}ms | "
        f"Nota: {result.security.grade} ({result.security.score}/100)"
    )

    violations_text = (
        "\n".join(f"• {v}" for v in all_violations)
        if all_violations
        else "Nenhuma violação detectada."
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Anhangá SRE & DevSecOps — {result.target_url}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Status:*\n{status_label}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Nota de Segurança:*\n{result.security.grade} ({result.security.score}/100)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Latência Total:*\n{result.timings.total_ms:.2f} ms (P95: {p95_ms:.2f} ms)",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*TTFB:*\n{result.timings.ttfb_ms:.2f} ms",
                },
                {"type": "mrkdwn", "text": f"*Status TLS:*\n{tls_status}"},
                {
                    "type": "mrkdwn",
                    "text": f"*IP Resolvido:*\n{result.resolved_ip or 'N/A'}",
                },
            ],
        },
    ]

    if all_violations:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Violações / Alertas:*\n{violations_text}",
                },
            }
        )

    attachments = [
        {
            "color": color,
            "fallback": summary_text,
            "fields": [
                {
                    "title": "Latência Total",
                    "value": f"{result.timings.total_ms:.2f} ms",
                    "short": True,
                },
                {
                    "title": "TTFB",
                    "value": f"{result.timings.ttfb_ms:.2f} ms",
                    "short": True,
                },
                {
                    "title": "Nota de Segurança",
                    "value": f"{result.security.grade} ({result.security.score}/100)",
                    "short": True,
                },
                {
                    "title": "Status TLS",
                    "value": tls_status,
                    "short": True,
                },
                {
                    "title": "Violações",
                    "value": violations_text,
                    "short": False,
                },
            ],
        }
    ]

    return {
        "text": summary_text,
        "blocks": blocks,
        "attachments": attachments,
    }


def build_teams_payload(
    result: ProbeResult, violations: list[str] | None = None
) -> dict[str, Any]:
    """Constrói payload Microsoft Teams no formato MessageCard com sections e facts."""
    all_violations = _collect_violations(result, violations)
    if not result.is_up:
        theme_color = "EF4444"
        status_label = f"OFFLINE ({result.status_code or 'ERR'})"
    elif all_violations:
        theme_color = "F59E0B"
        status_label = f"ALERTA SLO/SEC (HTTP {result.status_code})"
    else:
        theme_color = "10B981"
        status_label = f"ONLINE (HTTP {result.status_code})"

    tls_status = _format_tls_status(result)
    violations_str = "; ".join(all_violations) if all_violations else "Nenhuma"

    facts = [
        {"name": "Alvo", "value": result.target_url},
        {"name": "Status", "value": status_label},
        {"name": "Latência Total", "value": f"{result.timings.total_ms:.2f} ms"},
        {"name": "TTFB", "value": f"{result.timings.ttfb_ms:.2f} ms"},
        {
            "name": "Nota de Segurança",
            "value": f"{result.security.grade} ({result.security.score}/100)",
        },
        {"name": "Status TLS", "value": tls_status},
        {"name": "Violações", "value": violations_str},
    ]

    return {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": f"Anhangá Alert: {result.target_url} ({status_label})",
        "title": f"Anhangá Auditoria de Borda & SRE — {result.target_url}",
        "sections": [
            {
                "activityTitle": f"Diagnóstico: {result.target_url}",
                "activitySubtitle": f"Status: {status_label}",
                "facts": facts,
                "markdown": True,
            }
        ],
    }


def build_telegram_payload(
    result: ProbeResult,
    violations: list[str] | None = None,
    chat_id: str | None = None,
) -> dict[str, Any]:
    """Constrói payload para a API de Bots do Telegram."""
    all_violations = _collect_violations(result, violations)
    if not result.is_up:
        badge = "🔴 OFFLINE"
    elif all_violations:
        badge = "🟡 ALERTA"
    else:
        badge = "🟢 ONLINE"

    tls_status = _format_tls_status(result)
    lines = [
        f"<b>🔥 Anhangá SRE Alert — {badge}</b>",
        f"<b>Alvo:</b> <code>{result.target_url}</code>",
        f"<b>HTTP Status:</b> {result.status_code or 'ERR'} ({result.http_version or 'N/A'})",
        f"<b>Latência Total:</b> {result.timings.total_ms:.2f} ms",
        f"<b>TTFB:</b> {result.timings.ttfb_ms:.2f} ms",
        f"<b>Nota de Segurança:</b> {result.security.grade} ({result.security.score}/100)",
        f"<b>Status TLS:</b> {tls_status}",
    ]
    if all_violations:
        lines.append("<b>Violações:</b>")
        for v in all_violations:
            lines.append(f"• {v}")

    return {
        "chat_id": chat_id or "",
        "text": "\n".join(lines),
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }


def build_webhook_payload(
    result: ProbeResult,
    provider: str = "slack",
    violations: list[str] | None = None,
    chat_id: str | None = None,
) -> dict[str, Any]:
    """Despacha a construção do payload de acordo com o provedor."""
    resolved = detect_webhook_provider("", provider)
    if resolved == "teams":
        return build_teams_payload(result, violations=violations)
    if resolved == "telegram":
        return build_telegram_payload(result, violations=violations, chat_id=chat_id)
    return build_slack_payload(result, violations=violations)


async def send_webhook_alert(
    webhook_url: str,
    result: ProbeResult,
    provider: str = "auto",
    violations: list[str] | None = None,
    chat_id: str | None = None,
    allow_private: bool = False,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """
    Valida a URL do webhook contra SSRF (resolve_and_validate_host + IP pinning)
    e envia a notificação HTTP POST assíncrona.
    """
    raw_url = (webhook_url or "").strip()
    if not raw_url:
        raise ValueError("URL de webhook vazia.")

    parsed = urlparse(raw_url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFBlockedError(
            raw_url,
            f"Bloqueado pelo Guardião Anti-SSRF: esquema '{scheme}' não permitido no webhook.",
        )

    host = parsed.hostname
    if not host:
        raise ValueError("URL de webhook inválida: hostname ausente.")
    port = parsed.port or (443 if scheme == "https" else 80)

    resolved_ip, _ = await resolve_and_validate_host(
        host=host,
        port=port,
        allow_private=allow_private,
        dns_timeout=min(timeout, 3.0),
    )

    resolved_provider = detect_webhook_provider(raw_url, provider)
    payload = build_webhook_payload(
        result=result,
        provider=resolved_provider,
        violations=violations,
        chat_id=chat_id,
    )

    backend = InstrumentedPinnedNetworkBackend(allow_private=allow_private)
    backend.pinned_ips[host.lower()] = resolved_ip
    transport = _create_instrumented_transport(backend, verify=True, http2=False)

    async with httpx.AsyncClient(
        transport=transport,
        follow_redirects=False,
        timeout=httpx.Timeout(timeout),
    ) as client:
        resp = await client.post(raw_url, json=payload)

    return {
        "sent": 200 <= resp.status_code < 300,
        "status_code": resp.status_code,
        "provider": resolved_provider,
        "resolved_ip": resolved_ip,
        "payload": payload,
    }
