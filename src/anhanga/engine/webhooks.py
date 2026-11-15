import html
import typing
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from anhanga.engine.config import webhook_provider_from_url
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

    return webhook_provider_from_url(webhook_url) or "slack"  # type: ignore[return-value]


def _ms(result: ProbeResult, value: float) -> str:
    """Latência formatada; sem resposta do alvo não há medição (0 ms seria mentira)."""
    return "N/D" if result.status_code is None else f"{value:.2f} ms"


def _grade_text(result: ProbeResult) -> str:
    return "N/D" if result.status_code is None else f"{result.security.grade} ({result.security.score}/100)"


def _format_tls_status(result: ProbeResult) -> str:
    if result.tls is None:
        return "N/A (HTTP sem TLS)"
    if not result.tls.valid:
        reason = result.tls.validation_error
        return f"INVÁLIDO ({reason})" if reason else "INVÁLIDO"
    days = (
        f"{result.tls.days_remaining}d restantes"
        if result.tls.days_remaining is not None
        else "válido"
    )
    proto = result.tls.protocol or "TLS"
    warn = " [EXPIRANDO]" if result.tls.alert_expiring else ""
    return f"Válido ({proto}, {days}){warn}"


def _collect_violations(
    result: ProbeResult, violations: list[str] | None = None, event: str | None = None
) -> list[str]:
    """Mensagens do payload. As do AlertManager são a fonte de verdade; o estado do resultado só completa o
    que elas NÃO cobrem (uso avulso/CLI), por tópico e não por igualdade de texto: o texto divergia
    ("expira em" × "expirando em") e a linha saía duplicada. Em lembrete e recuperação nada é acrescentado:
    as mensagens já descrevem o que persiste ou foi resolvido ("...: resolvido")."""
    items = list(violations) if violations else []

    def covered(*needles: str) -> bool:
        return any(all(n in v.lower() for n in needles) for v in items)

    # O motivo do OFFLINE vale em alerta e lembrete (não na recuperação: o selo seria RECUPERADO ao lado de OFFLINE): um lembrete/reenvio cujas mensagens estejam vazias ou
    # genéricas não pode mostrar o selo vermelho sem razão.
    if event != "recovery" and not result.is_up and not any("offline" in v.lower() or "down" in v.lower() for v in items):
        reason = result.error or f"HTTP {result.status_code or 'ERR'}"
        items.insert(0, f"Alvo OFFLINE: {reason}")
    if event in ("recovery", "reminder"):
        return items  # TLS: as mensagens do evento já descrevem o que persiste/foi resolvido
    if result.health == "degraded" and not covered("certificado tls", "inválid"):
        reason = (result.tls.validation_error if result.tls else None) or "validação falhou"
        items.append(f"Certificado TLS inválido: {reason}")
    if result.tls and result.tls.alert_expiring and result.tls.days_remaining is not None:
        if not any(
            "certificado tls" in v.lower() and any(f in v.lower() for f in ("expira em", "expirando", "expirado há"))
            for v in items
        ):
            days = result.tls.days_remaining
            items.append(
                f"Certificado TLS expirado há {-days} dias" if days < 0 else f"Certificado TLS expira em {days} dias"
            )
    return items


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _fit_violations(
    violations: list[str], limit: int, per_item: int = 500, render: "typing.Callable[[str], str] | None" = None
) -> list[str]:
    """Cabe as violações no limite do canal (Slack: 3000 por bloco de texto; Telegram: 4096 por mensagem).

    O tamanho é medido no texto JÁ RENDERIZADO (`render`: marcador + escape HTML, que pode multiplicar o texto por 4 a 6),
    cada linha é cortada em `per_item` e as últimas são omitidas com "… (+N omitidas)". A 1ª violação sempre entra (encolhida
    até caber): um alerta sem nenhum motivo é pior que um motivo cortado. Cortar o texto BRUTO, antes de renderizar, evita
    partir uma entidade HTML no meio (`&#x27`)."""
    render = render or (lambda v: v)
    out: list[str] = []
    used = 0
    reserve = 60  # para a linha "… (+N omitidas)"
    for i, v in enumerate(violations):
        raw = _clip(str(v), per_item)
        line = render(raw)
        if i == 0:
            while len(line) + 1 > max(limit - reserve, 80) and len(raw) > 40:
                raw = _clip(raw, max(40, len(raw) // 2))
                line = render(raw)
        elif used + len(line) + 1 > limit - reserve:
            out.append(render(f"… (+{len(violations) - i} omitidas)"))
            break
        out.append(line)
        used += len(line) + 1
    return out


def build_slack_payload(
    result: ProbeResult, violations: list[str] | None = None, event: str | None = None
) -> dict[str, Any]:
    """Constrói payload Slack (Block Kit + Attachments coloridos)."""
    all_violations = _collect_violations(result, violations, event)
    if not result.is_up:
        color = "#ef4444"
        status_label = f"🔴 OFFLINE ({result.status_code or 'ERR'})"
    elif all_violations:
        color = "#f59e0b"
        status_label = f"🟡 ALERTA SLO/SEC (HTTP {result.status_code})"
    else:
        color = "#10b981"
        status_label = f"🟢 ONLINE (HTTP {result.status_code})"
    if event == "recovery":
        color = "#10b981"
        status_label = f"🟢 RECUPERADO (HTTP {result.status_code})"
    elif event == "reminder":
        status_label += " — LEMBRETE (problema persiste)"

    tls_status = _format_tls_status(result)
    # P95 só com amostras suficientes (n >= 20); antes, sem amostragem, a latência total saía rotulada como "P95".
    p95_suffix = (
        f" (P95: {_ms(result, result.sampling.p95_ms)})" if (result.sampling and result.sampling.p95_valid) else ""
    )
    summary_text = (
        f"[Anhangá] {status_label} — {result.target_url} | "
        f"Total: {_ms(result, result.timings.total_ms)} | TTFB: {_ms(result, result.timings.ttfb_ms)} | "
        f"Nota: {_grade_text(result)}"
    )

    violations_text = (
        "\n".join(_fit_violations(all_violations, 2800, render=lambda v: f"• {v}"))
        if all_violations
        else "Nenhuma violação detectada."
    )

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                # `plain_text` de header: no máx. 150 caracteres (senão o Slack recusa o payload inteiro, 400 invalid_blocks)
                "text": _clip(f"Anhangá SRE & DevSecOps — {result.target_url}", 150),
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Status:*\n{status_label}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Nota de Segurança:*\n{_grade_text(result)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Latência Total:*\n{_ms(result, result.timings.total_ms)}{p95_suffix}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*TTFB:*\n{_ms(result, result.timings.ttfb_ms)}",
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
                    "value": f"{_ms(result, result.timings.total_ms)}",
                    "short": True,
                },
                {
                    "title": "TTFB",
                    "value": f"{_ms(result, result.timings.ttfb_ms)}",
                    "short": True,
                },
                {
                    "title": "Nota de Segurança",
                    "value": f"{_grade_text(result)}",
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
    result: ProbeResult, violations: list[str] | None = None, event: str | None = None
) -> dict[str, Any]:
    """Constrói payload Microsoft Teams no formato MessageCard com sections e facts."""
    all_violations = _collect_violations(result, violations, event)
    if not result.is_up:
        theme_color = "EF4444"
        status_label = f"OFFLINE ({result.status_code or 'ERR'})"
    elif all_violations:
        theme_color = "F59E0B"
        status_label = f"ALERTA SLO/SEC (HTTP {result.status_code})"
    else:
        theme_color = "10B981"
        status_label = f"ONLINE (HTTP {result.status_code})"
    if event == "recovery":
        theme_color = "10B981"
        status_label = f"RECUPERADO (HTTP {result.status_code})"
    elif event == "reminder":
        status_label += " — LEMBRETE (problema persiste)"

    tls_status = _format_tls_status(result)
    violations_str = "; ".join(all_violations) if all_violations else "Nenhuma"

    facts = [
        {"name": "Alvo", "value": result.target_url},
        {"name": "Status", "value": status_label},
        {"name": "Latência Total", "value": f"{_ms(result, result.timings.total_ms)}"},
        {"name": "TTFB", "value": f"{_ms(result, result.timings.ttfb_ms)}"},
        {
            "name": "Nota de Segurança",
            "value": f"{_grade_text(result)}",
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
    event: str | None = None,
) -> dict[str, Any]:
    """Constrói payload para a API de Bots do Telegram."""
    all_violations = _collect_violations(result, violations, event)
    if not result.is_up:
        badge = "🔴 OFFLINE"
    elif all_violations:
        badge = "🟡 ALERTA"
    else:
        badge = "🟢 ONLINE"
    if event == "recovery":
        badge = "🟢 RECUPERADO"
    elif event == "reminder":
        badge += " — LEMBRETE"

    tls_str = html.escape(_clip(_format_tls_status(result), 300))
    target_url_escaped = html.escape(_clip(str(result.target_url), 400))
    http_ver_escaped = html.escape(str(result.http_version or "N/A"))
    grade_escaped = html.escape(_grade_text(result))

    lines = [
        f"<b>🔥 Anhangá SRE Alert — {badge}</b>",
        f"<b>Alvo:</b> <code>{target_url_escaped}</code>",
        f"<b>HTTP Status:</b> {result.status_code or 'ERR'} ({http_ver_escaped})",
        f"<b>Latência Total:</b> {_ms(result, result.timings.total_ms)}",
        f"<b>TTFB:</b> {_ms(result, result.timings.ttfb_ms)}",
        f"<b>Nota de Segurança:</b> {grade_escaped}",
        f"<b>Status TLS:</b> {tls_str}",
    ]
    if all_violations:
        lines.append("<b>Violações:</b>")
        # orçamento = 4096 menos o já usado; cada violação é medida DEPOIS de escapada (aspas e < & expandem 4-6x)
        budget = 4000 - len("\n".join(lines))
        lines.extend(_fit_violations(all_violations, budget, per_item=300, render=lambda v: f"• {html.escape(v)}"))

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
    event: str | None = None,
) -> dict[str, Any]:
    """Despacha a construção do payload de acordo com o provedor."""
    resolved = detect_webhook_provider("", provider)
    if resolved == "teams":
        return build_teams_payload(result, violations=violations, event=event)
    if resolved == "telegram":
        return build_telegram_payload(result, violations=violations, chat_id=chat_id, event=event)
    return build_slack_payload(result, violations=violations, event=event)


async def send_webhook_alert(
    webhook_url: str,
    result: ProbeResult,
    provider: str = "auto",
    violations: list[str] | None = None,
    chat_id: str | None = None,
    allow_private: bool = False,
    timeout: float = 5.0,
    event: str | None = None,
) -> dict[str, Any]:
    """
    Valida a URL do webhook contra SSRF (resolve_and_validate_host + IP pinning)
    e envia a notificação HTTP POST assíncrona.
    """
    raw_url = (webhook_url or "").strip()
    if not raw_url:
        raise ValueError("URL de webhook vazia.")

    try:
        parsed = urlparse(raw_url)
    except ValueError as exc:
        raise ValueError(f"URL de webhook malformada: {exc}") from exc
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
        event=event,
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
