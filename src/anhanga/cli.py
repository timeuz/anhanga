import argparse
import asyncio
import concurrent.futures
import json
from pathlib import Path
import re
import sqlite3
import sys
from typing import Any, NoReturn

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from anhanga import __version__
from anhanga.i18n import tr
from anhanga.engine.models import ProbeResult
from anhanga.engine.alerting import effective_total_ms, effective_ttfb_ms
from anhanga.engine.config import GRADE_RANK, parse_duration_ms
from anhanga.engine.probe import execute_probe
from anhanga.engine.webhooks import send_webhook_alert

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"


class CLIArgumentError(ValueError):
    """Exceção interna para argumentos inválidos na CLI (exit code 3)."""


class _NonExitingArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CLIArgumentError(message)


def _is_execution_or_ssrf_error(error_msg: str | None, error_code: str | None = None) -> bool:
    """Identifica se o erro foi bloqueio Anti-SSRF, falha de DNS ou URL inválida (exit code 2)."""
    # só o `error_code` estruturado decide (a mensagem só diz que houve erro): o texto pode conter o padrão de uma
    # asserção do usuário (ex.: 'Erro de DNS') e não pode virar 'erro de execução' (exit 3).
    return bool(error_msg) and error_code in ("ssrf_blocked", "dns_error", "invalid_url")


def evaluate_probe_gates(
    result: ProbeResult,
    min_grade: str | None = None,
    max_ttfb_ms: float | None = None,
    max_total_ms: float | None = None,
    require_valid_cert: bool = True,
) -> tuple[bool, int, list[str]]:
    """
    Avalia os Quality Gates de SRE/DevSecOps sobre um ProbeResult.
    Retorna (passed, exit_code, violations):
    - exit_code 3: Erro de DNS, bloqueio Anti-SSRF, target inválido ou argumento/configuração inválidos
    - exit_code 2: Nota de segurança abaixo do mínimo exigido (--min-grade)
    - exit_code 1: Alvo offline, certificado TLS inválido, falha de SLO (TTFB/Total) ou Content Assertion falhou
    - exit_code 0: Todas as verificações passaram
    """
    violations: list[str] = []

    if _is_execution_or_ssrf_error(result.error, result.error_code):
        violations.append(result.error or tr("Erro de DNS ou bloqueio Anti-SSRF.", "DNS error or Anti-SSRF block."))
        return False, 3, violations

    slo_or_conn_failed = False

    if not result.is_up:
        if result.assertions and not result.assertions.passed and result.status_code and 200 <= result.status_code < 400:
            pass
        else:
            reason = result.error or f"HTTP {result.status_code or 'ERR'}"
            violations.append(tr(f"Alvo OFFLINE: {reason}", f"Target OFFLINE: {reason}"))
            slo_or_conn_failed = True

    if require_valid_cert and result.health == "degraded":
        reason = (result.tls.validation_error if result.tls else None) or tr(
            "validação do certificado falhou", "certificate validation failed"
        )
        violations.append(tr(f"Certificado TLS inválido: {reason}", f"Invalid TLS certificate: {reason}"))
        slo_or_conn_failed = True

    if result.assertions and not result.assertions.passed:
        for fail_msg in result.assertions.failures:
            violations.append(f"Content Assertion: {fail_msg}")
        slo_or_conn_failed = True

    ttfb_ms = effective_ttfb_ms(result)
    if max_ttfb_ms is not None and ttfb_ms > max_ttfb_ms:
        violations.append(
            tr(
                f"SLO de TTFB violado: {ttfb_ms:.2f}ms excede o limite de {max_ttfb_ms:.2f}ms.",
                f"TTFB SLO violated: {ttfb_ms:.2f}ms exceeds the {max_ttfb_ms:.2f}ms limit.",
            )
        )
        slo_or_conn_failed = True

    total_ms = effective_total_ms(result)
    if max_total_ms is not None and total_ms > max_total_ms:
        violations.append(
            tr(
                f"SLO de Latência Total violado: {total_ms:.2f}ms excede o limite de {max_total_ms:.2f}ms.",
                f"Total Latency SLO violated: {total_ms:.2f}ms exceeds the {max_total_ms:.2f}ms limit.",
            )
        )
        slo_or_conn_failed = True

    grade_failed = False
    if min_grade:
        norm_min = min_grade.strip().upper()
        if norm_min not in GRADE_RANK:
            raise CLIArgumentError(
                tr(
                    f"Nota mínima inválida '{min_grade}'. Escolha entre: {', '.join(GRADE_RANK.keys())}.",
                    f"Invalid minimum grade '{min_grade}'. Choose one of: {', '.join(GRADE_RANK.keys())}.",
                )
            )
        actual_grade = (result.security.grade or "F").upper()
        if GRADE_RANK.get(actual_grade, 1) < GRADE_RANK[norm_min]:
            violations.append(
                tr(
                    f"Nota de segurança insuficiente: obtido '{actual_grade}' (score {result.security.score}/100), mínimo exigido '{norm_min}'.",
                    f"Insufficient security grade: got '{actual_grade}' (score {result.security.score}/100), required minimum '{norm_min}'.",
                )
            )
            grade_failed = True

    if slo_or_conn_failed:
        return False, 1, violations
    if grade_failed:
        return False, 2, violations
    if violations:
        return False, 1, violations
    return True, 0, []


def _severity_to_sarif_level(severity: str) -> str:
    sev = (severity or "medium").lower()
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    return "note"


def build_sarif_report(
    result: ProbeResult,
    violations: list[str],
    exit_code: int,
) -> dict[str, Any]:
    """Constrói relatório SARIF v2.1.0 completo para integração com GitHub Code Scanning / GitLab / DefectDojo."""
    rules_by_id: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    target_uri = result.target_url

    def _ensure_rule(
        rule_id: str,
        name: str,
        short_desc: str,
        full_desc: str,
        help_text: str,
        level: str = "warning",
    ) -> None:
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": name,
                "shortDescription": {"text": short_desc},
                "fullDescription": {"text": full_desc},
                "help": {"text": help_text},
                "defaultConfiguration": {"level": level},
            }

    # violações dos quality gates (SLO, nota, disponibilidade, anti-SSRF)
    for idx, violation in enumerate(violations, start=1):
        # classifica pelo PREFIXO que o `evaluate_probe_gates` gera (e pelo exit 3 = DNS/SSRF/argumento), nunca por
        # substring solta: um padrão `total` ou um host `cdns.exemplo.com` não podem mudar a regra.
        if violation.startswith(("Certificado TLS inválido:", "Invalid TLS certificate:")):
            rule_id = "ANHANGA-TLS-INVALID"
            rule_name = "InvalidTLSCertificate"
            short_desc = tr(
                "Certificado TLS inválido (expirado, hostname divergente ou cadeia não confiável)",
                "Invalid TLS certificate (expired, hostname mismatch or untrusted chain)",
            )
        elif exit_code == 3:
            rule_id = "ANHANGA-SSRF-OR-DNS"
            rule_name = "SSRFOrDNSValidationFailure"
            short_desc = tr("Bloqueio Anti-SSRF ou falha de resolução DNS", "Anti-SSRF block or DNS resolution failure")
        elif violation.startswith(("SLO de TTFB", "TTFB SLO")):
            rule_id = "ANHANGA-SLO-TTFB"
            rule_name = "TTFBSLOViolation"
            short_desc = tr("Violação de SLO de Time to First Byte (TTFB)", "Time to First Byte (TTFB) SLO violation")
        elif violation.startswith(("SLO de Latência Total", "Total Latency SLO")):
            rule_id = "ANHANGA-SLO-TOTAL"
            rule_name = "TotalLatencySLOViolation"
            short_desc = tr("Violação de SLO de Latência Total", "Total latency SLO violation")
        elif violation.startswith(("Nota de segurança", "Insufficient security grade")):
            rule_id = "ANHANGA-GATE-SECURITY-GRADE"
            rule_name = "MinimumSecurityGradeViolation"
            short_desc = tr(
                "Nota de segurança abaixo do mínimo exigido pelo Quality Gate",
                "Security grade below the minimum required by the Quality Gate",
            )
        elif violation.startswith(("Alvo OFFLINE:", "Target OFFLINE:")):
            rule_id = "ANHANGA-AVAILABILITY"
            rule_name = "TargetUnavailable"
            short_desc = tr("Alvo indisponível ou retornando erro HTTP", "Target unavailable or returning an HTTP error")
        elif violation.startswith("Content Assertion:"):
            rule_id = "ANHANGA-ASSERTION"
            rule_name = "ContentAssertionFailure"
            short_desc = tr("Falha em verificação de asserção de conteúdo", "Content assertion check failed")
        else:
            rule_id = f"ANHANGA-GATE-{idx}"
            rule_name = f"QualityGateViolation{idx}"
            short_desc = tr("Violação de Quality Gate na auditoria", "Quality Gate violation in the audit")

        _ensure_rule(
            rule_id=rule_id,
            name=rule_name,
            short_desc=short_desc,
            full_desc=violation,
            help_text=tr(
                "Verifique a disponibilidade, latência de borda e cabeçalhos de segurança do endpoint.",
                "Check the endpoint's availability, edge latency and security headers.",
            ),
            level="error",
        )
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": violation},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target_uri},
                        }
                    }
                ],
            }
        )

    # achados de segurança (missing_findings)
    for finding in result.security.missing_findings:
        rule_id = finding.id or f"SEC-{re.sub(r'[^A-Z0-9]+', '-', finding.header.upper()).strip('-')}"
        level = _severity_to_sarif_level(finding.severity)
        _ensure_rule(
            rule_id=rule_id,
            name=finding.header,
            short_desc=f"{finding.header} ({finding.category})",
            full_desc=finding.description,
            help_text=finding.remediation,
            level=level,
        )
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"[{finding.header}] {finding.description} | {tr('Remediação', 'Remediation')}: {finding.remediation}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": target_uri},
                        }
                    }
                ],
            }
        )

    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA_URI,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Anhangá",
                        "version": __version__,
                        "informationUri": "https://github.com/timeuz/anhanga",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "invocations": [
                    {
                        # a ferramenta rodou com sucesso mesmo quando um gate reprova; só o exit 3 (erro de execução ou de argumento)
                        # conta como falha de execução.
                        "executionSuccessful": exit_code != 3,
                        "exitCode": exit_code,
                    }
                ],
                "results": sarif_results,
            }
        ],
    }


def build_json_report(
    result: ProbeResult,
    violations: list[str],
    exit_code: int,
    thresholds: dict[str, Any],
) -> dict[str, Any]:
    """Constrói o payload JSON padronizado para pipelines CI/CD."""
    return {
        "passed": exit_code == 0,
        "exit_code": exit_code,
        "violations": violations,
        "thresholds": thresholds,
        "result": result.model_dump(mode="json"),
    }


def _revocation_text(tls: Any) -> str:
    rev = getattr(tls, "revocation", None)
    if rev is None:
        return tr("não verificada", "not checked")
    labels = {
        "good": tr("não revogado", "not revoked"),
        "revoked": tr("[bold red]REVOGADO[/bold red]", "[bold red]REVOKED[/bold red]"),
        "unknown": tr("desconhecido pelo respondedor", "unknown to the responder"),
        "unavailable": tr("não verificável", "cannot be checked"),
        "error": tr("falha na checagem", "check failed"),
    }
    method = f" ({rev.method.upper()})" if rev.method and rev.status != "unavailable" else ""
    return labels.get(rev.status, escape(str(rev.status))) + method


def _protocols_text(tls: Any) -> str | None:
    enum = getattr(tls, "enumeration", None)
    if enum is None:
        return None
    parts = []
    for p in enum.protocols:
        if p.status == "accepted":
            bad = p.protocol in ("TLSv1", "TLSv1.1") or p.weak_ciphers
            weak = tr(f", {len(p.weak_ciphers)} fracas", f", {len(p.weak_ciphers)} weak") if p.weak_ciphers else ""
            tag = f"{p.protocol} ({len(p.ciphers)} " + tr("cifras", "ciphers") + weak + ")"
            parts.append(f"[bold red]{tag}[/bold red]" if bad else f"[green]{tag}[/green]")
        elif p.status == "unknown":
            parts.append(f"[yellow]{p.protocol}?[/yellow]")
    text = ", ".join(parts) if parts else tr("nenhum protocolo testável aceito", "no testable protocol accepted")
    if enum.legacy_ciphers_untested:
        text += " [dim]" + tr("(RC4/3DES não testáveis neste OpenSSL)", "(RC4/3DES cannot be tested with this OpenSSL)") + "[/dim]"
    return text


def render_rich_report(
    result: ProbeResult,
    violations: list[str],
    exit_code: int,
    thresholds: dict[str, Any],
) -> str:
    """Renderiza relatório tático com Rich para exibição no terminal e retorna versão em texto."""
    console = Console(record=True, width=100)
    na = tr("N/D", "N/A")

    if result.health == "up":
        status_badge = f"[bold green]ONLINE (HTTP {result.status_code})[/bold green]"
    elif result.health == "degraded":
        tls_reason = escape((result.tls.validation_error if result.tls else None) or tr("TLS inválido", "invalid TLS"))
        status_badge = (
            f"[bold yellow]{tr('DEGRADADO', 'DEGRADED')} (HTTP {result.status_code}, "
            f"{tr('TLS inválido', 'invalid TLS')}: {tls_reason})[/bold yellow]"
        )
    else:
        status_badge = f"[bold red]OFFLINE ({escape(str(result.error or result.status_code or 'ERR'))})[/bold red]"
    grade = result.security.grade
    grade_color = (
        "green"
        if grade in ("A+", "A")
        else ("yellow" if grade in ("B", "C") else "red")
    )

    header_text = Text.from_markup(
        f"[bold orange1]🔥 {tr('ANHANGÁ — AUDITORIA SRE & DEVSECOPS', 'ANHANGÁ — SRE & DEVSECOPS AUDIT')}[/bold orange1]\n"
        f"{tr('Alvo', 'Target')}: [bold cyan]{escape(result.target_url)}[/bold cyan]  |  "
        f"IP: [bold]{escape(result.resolved_ip or 'N/A')}[/bold]  |  "
        f"Status: {status_badge}  |  "
        f"{tr('Nota', 'Grade')}: [bold {grade_color}]{grade} ({result.security.score}/100)[/bold {grade_color}]"
    )
    console.print(Panel(header_text, border_style="orange1"))

    # tabela do waterfall de latência
    wf_table = Table(
        title=tr("Waterfall de Latência Não-Cumulativa (ms)", "Non-cumulative Latency Waterfall (ms)"),
        show_header=True,
        header_style="bold cyan",
    )
    wf_table.add_column(tr("Fase", "Phase"), style="bold")
    wf_table.add_column(tr("Janela (start → end)", "Window (start → end)"), justify="right")
    wf_table.add_column(tr("Duração (ms)", "Duration (ms)"), justify="right")
    wf_table.add_column(tr("Status SLO", "SLO status"), justify="center")
    wf_table.add_column(tr("Gargalo", "Bottleneck"), justify="center")

    for p in result.timings.phases:
        slo_color = (
            "green"
            if p.slo_status == "ok"
            else ("yellow" if p.slo_status == "warning" else "red")
        )
        wf_table.add_row(
            p.label,
            f"{p.start_ms:.2f} → {p.end_ms:.2f} ms",
            f"{p.duration_ms:.2f} ms",
            f"[{slo_color}]{p.slo_status.upper()}[/{slo_color}]",
            tr("🔥 SIM", "🔥 YES") if p.is_dominant else "-",
        )
    wf_table.add_row(
        "[bold]" + tr("TOTAL (1ª Amostra Fria)", "TOTAL (1st cold sample)") + "[/bold]",
        f"0.00 → {result.timings.total_ms:.2f} ms",
        f"[bold]{result.timings.total_ms:.2f} ms[/bold]",
        "-",
        f"{tr('Dominante', 'Dominant')}: {result.timings.dominant_phase or 'N/A'}",
    )
    console.print(wf_table)

    # rede x servidor: RTT de rede e processamento do servidor
    rtt_text = (
        f"🌐 [bold cyan]{tr('Decomposição Física', 'Physical breakdown')}:[/bold cyan] "
        f"{tr('RTT de Rede Estimado', 'Estimated network RTT')}: [bold]{result.timings.estimated_rtt_ms:.2f} ms[/bold]  |  "
        f"{tr('Processamento Servidor (TTFB − RTT)', 'Server processing (TTFB − RTT)')}: [bold]"
        f"{na if result.timings.server_processing_ms is None else format(result.timings.server_processing_ms, '.2f') + ' ms'}"
        "[/bold]"
    )
    for note in result.timings.timing_notes:
        rtt_text += f"\nℹ️ {note}"
    console.print(Panel(rtt_text, border_style="blue"))

    # estatísticas da amostragem (P50 / P95 / P99 / jitter / conexão fria x keep-alive)
    samp = result.sampling
    warm_str = (
        f"{samp.warm_avg_total_ms:.2f} ms"
        if samp.warm_avg_total_ms is not None
        else tr("N/A (1 amostra)", "N/A (1 sample)")
    )
    stats_body = (
        f"{tr('Destaque', 'Highlight')}: [bold green]{samp.headline_label}: {samp.headline_total_ms:.2f} ms[/bold green]  |  "
        f"{tr('Amostras', 'Samples')}: [bold]{samp.samples_count}x[/bold]  |  "
        f"Jitter: [bold]{samp.jitter_ms:.2f} ms[/bold]\n"
        f"{tr('Percentis', 'Percentiles')}: P50=[bold]{samp.p50_ms:.2f}ms[/bold], "
        f"P95=[bold]{f'{samp.p95_ms:.2f}ms' if samp.p95_valid else 'N/A (n<20)'}[/bold], "
        f"P99=[bold]{f'{samp.p99_ms:.2f}ms' if samp.p99_valid else 'N/A (n<100)'}[/bold]\n"
        f"{tr('Conexão Fria (1ª)', 'Cold connection (1st)')}: [bold]{samp.cold_total_ms:.2f} ms[/bold]  |  "
        f"{tr('Keep-Alive Reusada', 'Reused keep-alive')}: [bold]{warm_str}[/bold]"
    )
    if samp.sample_size_notice:
        stats_body += f"\n[dim yellow]ℹ️ {samp.sample_size_notice}[/dim yellow]"

    console.print(
        Panel(
            stats_body,
            title=tr(
                "Estatísticas SRE (Latência Típica Mediana & Percentis)",
                "SRE statistics (typical median latency & percentiles)",
            ),
            border_style="cyan",
        )
    )

    # alerta de falha em modo comum (se detectado)
    if result.common_mode_failure_warning:
        console.print(
            Panel(
                f"[bold red]⚠️ {tr('FALHA DE MODO COMUM DETECTADA', 'COMMON-MODE FAILURE DETECTED')}:[/bold red] "
                f"{escape(result.common_mode_failure_warning)}",
                border_style="red",
            )
        )

    # resumo de TLS e da porta 80
    if result.tls:
        tls_valid_str = (
            "[bold green]" + tr("VÁLIDO", "VALID") + "[/bold green]"
            if result.tls.valid
            else "[bold red]" + tr("INVÁLIDO", "INVALID") + "[/bold red]"
        )
        port80_info = (
            f"  |  {tr('Porta 80 (HTTP→HTTPS)', 'Port 80 (HTTP→HTTPS)')}: [bold]{escape(result.http_port_80_status or 'N/A')}[/bold]"
            if result.http_port_80_status
            else ""
        )
        console.print(
            Panel(
                f"{tr('Certificado', 'Certificate')}: {tls_valid_str}  |  {tr('Protocolo', 'Protocol')}: [bold]{escape(result.tls.protocol or 'N/A')}[/bold]  |  "
                f"{tr('Cifra', 'Cipher')}: [bold]{escape(result.tls.cipher or 'N/A')}[/bold]{port80_info}\n"
                f"{tr('Emissor', 'Issuer')}: {escape(result.tls.issuer or 'N/A')}  |  "
                f"{tr('Dias Restantes', 'Days left')}: [bold]{result.tls.days_remaining if result.tls.days_remaining is not None else 'N/A'}[/bold] "
                f"({'N/A' if result.tls.relative_validity_percent_remaining is None else format(result.tls.relative_validity_percent_remaining, '.1f')}% {tr('restante', 'remaining')})  |  "
                f"OCSP: {escape(str(result.tls.ocsp_status))}  |  "
                f"{tr('Revogação', 'Revocation')}: {_revocation_text(result.tls)}"
                + (f"\n{tr('Protocolos aceitos', 'Accepted protocols')}: {_protocols_text(result.tls)}" if _protocols_text(result.tls) else "")
                + (f"\n{tr('Motivo da invalidez', 'Reason for invalidity')}: {escape(result.tls.validation_error)}" if not result.tls.valid and result.tls.validation_error else ""),
                title=tr("Inspeção de Certificado TLS", "TLS certificate inspection"),
                border_style="cyan",
            )
        )

    # resultado dos quality gates
    if exit_code == 0:
        console.print(
            Panel(
                "[bold green]✅ " + tr("QUALITY GATES APROVADOS", "QUALITY GATES PASSED") + " (Exit Code 0)[/bold green]",
                border_style="green",
            )
        )
    else:
        v_lines = "\n".join(f"• [bold red]{escape(v)}[/bold red]" for v in violations)
        console.print(
            Panel(
                f"[bold red]❌ {tr('FALHA NOS QUALITY GATES', 'QUALITY GATES FAILED')} (Exit Code {exit_code})[/bold red]\n{v_lines}",
                title=tr(f"Violações Detectadas ({len(violations)})", f"Violations Detected ({len(violations)})"),
                border_style="red",
            )
        )

    return console.export_text()


def _build_parser() -> _NonExitingArgumentParser:
    parser = _NonExitingArgumentParser(
        prog="anhanga",
        description=tr("Anhangá — Auditor Tático de Borda, TLS, Latência e DevSecOps para SRE e CI/CD", "Anhangá — tactical edge, TLS, latency and DevSecOps auditor for SRE and CI/CD"),
    )
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser(
        "check",
        help=tr("Executa auditoria com Quality Gates de SLO e DevSecOps para pipelines CI/CD", "Runs an audit with SLO and DevSecOps Quality Gates for CI/CD pipelines"),
    )
    check_parser.add_argument(
        "target_positional",
        nargs="?",
        default=None,
        help=tr("URL ou hostname alvo para auditoria", "Target URL or hostname to audit"),
    )
    check_parser.add_argument(
        "--url",
        "-u",
        dest="target_option",
        default=None,
        help=tr("URL ou hostname alvo para auditoria", "Target URL or hostname to audit"),
    )
    check_parser.add_argument(
        "--min-grade",
        default=None,
        help=tr("Nota mínima de segurança exigida (A+, A, B, C, D, F)", "Minimum required security grade (A+, A, B, C, D, F)"),
    )
    check_parser.add_argument(
        "--max-ttfb",
        default=None,
        help=tr("Limite máximo de TTFB (ex: 500ms, 0.5s ou 500)", "Maximum TTFB (e.g. 500ms, 0.5s or 500)"),
    )
    check_parser.add_argument(
        "--max-total",
        default=None,
        help=tr("Limite máximo de Latência Total (ex: 1000ms, 1.5s ou 1000)", "Maximum total latency (e.g. 1000ms, 1.5s or 1000)"),
    )
    check_parser.add_argument(
        "--samples",
        "-n",
        type=int,
        default=1,
        help=tr("Quantidade de amostras para cálculo de P50/P95/P99 e Jitter (default: 1)", "Number of samples for P50/P95/P99 and jitter (default: 1)"),
    )
    check_parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        default=5.0,
        help=tr("Timeout por requisição em segundos (default: 5.0)", "Per-request timeout in seconds (default: 5.0)"),
    )
    check_parser.add_argument(
        "--allow-private",
        action="store_true",
        default=False,
        help=tr("Permite sondar IPs de rede interna / loopback (ambientes de Lab/CI local)", "Allows probing internal-network / loopback IPs (lab / local CI environments)"),
    )
    check_parser.add_argument(
        "--allow-invalid-cert",
        action="store_true",
        default=False,
        help=tr("Não reprova o gate quando o certificado TLS é inválido (por padrão reprova, exit 1)", "Does not fail the gate when the TLS certificate is invalid (it fails by default, exit 1)"),
    )
    check_parser.add_argument(
        "--format",
        "-f",
        choices=("text", "json", "sarif"),
        default="text",
        help=tr("Formato do relatório de saída: text, json ou sarif (default: text)", "Report output format: text, json or sarif (default: text)"),
    )
    check_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help=tr("Caminho opcional de arquivo para salvar o relatório gerado", "Optional file path to save the generated report"),
    )
    check_parser.add_argument(
        "--webhook-url",
        default=None,
        help=tr("URL opcional de Webhook (Slack, Microsoft Teams ou Telegram) para envio de alerta", "Optional webhook URL (Slack, Microsoft Teams or Telegram) to send an alert"),
    )
    check_parser.add_argument(
        "--webhook-provider",
        choices=("auto", "slack", "teams", "telegram"),
        default="auto",
        help=tr("Provedor de Webhook (default: auto)", "Webhook provider (default: auto)"),
    )
    check_parser.add_argument(
        "--telegram-chat-id",
        default=None,
        help=tr("Chat ID opcional para alertas via Telegram Bot API", "Optional chat ID for alerts via the Telegram Bot API"),
    )

    keygen_parser = subparsers.add_parser(
        "keygen",
        help=tr("Gera a chave da API (ANHANGA_API_KEY) e a grava em .env com permissão 0600", "Generates the API key (ANHANGA_API_KEY) and writes it to .env with 0600 permissions"),
    )
    keygen_parser.add_argument("--env-file", default=None, help=tr("Arquivo de destino (default: ./.env)", "Destination file (default: ./.env)"))
    keygen_parser.add_argument("--force", action="store_true", help=tr("Substitui uma chave já existente", "Replaces an existing key"))

    backup_parser = subparsers.add_parser(
        "backup",
        help=tr("Copia o banco SQLite de forma consistente (pode rodar com o servidor ativo)", "Copies the SQLite database consistently (can run while the server is up)"),
    )
    backup_parser.add_argument("destination", help=tr("Arquivo de destino da cópia", "Destination file for the copy"))
    backup_parser.add_argument("--db", default=None, help=tr("Banco de origem (default: ANHANGA_DB_PATH ou storage.path)", "Source database (default: ANHANGA_DB_PATH or storage.path)"))
    backup_parser.add_argument("--force", action="store_true", help=tr("Sobrescreve o destino se existir", "Overwrites the destination if it exists"))

    serve_parser = subparsers.add_parser(
        "serve",
        help=tr("Inicia o servidor Web e a API FastAPI do Anhangá", "Starts Anhangá's web server and FastAPI API"),
    )
    serve_parser.add_argument(
        "--host",
        "-H",
        default="127.0.0.1",
        help=tr("Endereço IP/host de escuta do servidor (default: 127.0.0.1)", "Server listen address/host (default: 127.0.0.1)"),
    )
    serve_parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=7890,
        help=tr("Porta TCP do servidor (default: 7890)", "Server TCP port (default: 7890)"),
    )
    serve_parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help=tr("Ativa hot-reload automático para desenvolvimento", "Enables automatic hot-reload for development"),
    )
    return parser


async def _run_check_async(args: argparse.Namespace) -> int:
    target_url = (args.target_option or args.target_positional or "").strip()
    if not target_url:
        raise CLIArgumentError(tr("URL alvo obrigatória. Informe posicionalmente ou via --url.", "Target URL is required. Pass it positionally or via --url."))

    if args.samples < 1 or args.samples > 50:
        raise CLIArgumentError(tr("--samples deve estar entre 1 e 50.", "--samples must be between 1 and 50."))
    if args.timeout <= 0:
        raise CLIArgumentError(tr("--timeout deve ser maior que zero.", "--timeout must be greater than zero."))

    min_grade: str | None = None
    if args.min_grade is not None:
        min_grade = args.min_grade.strip().upper()
        if min_grade not in GRADE_RANK:
            raise CLIArgumentError(
                tr(
                    f"Nota mínima inválida '{args.min_grade}'. Valores aceitos: {', '.join(GRADE_RANK.keys())}.",
                    f"Invalid minimum grade '{args.min_grade}'. Accepted values: {', '.join(GRADE_RANK.keys())}.",
                )
            )

    try:
        max_ttfb_ms = (
            parse_duration_ms(args.max_ttfb) if args.max_ttfb is not None else None
        )
        max_total_ms = (
            parse_duration_ms(args.max_total) if args.max_total is not None else None
        )
    except ValueError as exc:
        raise CLIArgumentError(str(exc)) from exc

    result = await execute_probe(
        raw_url=target_url,
        timeout=args.timeout,
        allow_private=args.allow_private,
        samples=args.samples,
    )

    _, exit_code, violations = evaluate_probe_gates(
        result=result,
        min_grade=min_grade,
        max_ttfb_ms=max_ttfb_ms,
        max_total_ms=max_total_ms,
        require_valid_cert=not args.allow_invalid_cert,
    )

    thresholds = {
        "min_grade": min_grade,
        "max_ttfb_ms": max_ttfb_ms,
        "max_total_ms": max_total_ms,
        "require_valid_cert": not args.allow_invalid_cert,
    }

    if args.webhook_url:
        try:
            await send_webhook_alert(
                webhook_url=args.webhook_url,
                result=result,
                provider=args.webhook_provider,
                violations=violations,
                chat_id=args.telegram_chat_id,
                allow_private=args.allow_private,
                timeout=args.timeout,
            )
        except Exception as wh_exc:
            print(f"[Anhangá Webhook Error] {wh_exc}", file=sys.stderr)

    output_content: str
    if args.format == "json":
        report_dict = build_json_report(
            result=result,
            violations=violations,
            exit_code=exit_code,
            thresholds=thresholds,
        )
        output_content = json.dumps(report_dict, ensure_ascii=False, indent=2)
        print(output_content)
    elif args.format == "sarif":
        sarif_dict = build_sarif_report(
            result=result,
            violations=violations,
            exit_code=exit_code,
        )
        output_content = json.dumps(sarif_dict, ensure_ascii=False, indent=2)
        print(output_content)
    else:
        output_content = render_rich_report(
            result=result,
            violations=violations,
            exit_code=exit_code,
            thresholds=thresholds,
        )

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_content, encoding="utf-8")

    return exit_code


def _is_loopback_host(host: str) -> bool:
    import ipaddress

    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip().strip("[]")).is_loopback
    except ValueError:
        return False


def _run_keygen(args: argparse.Namespace) -> int:
    from anhanga.envfile import generate_api_key

    try:
        path, key = generate_api_key(Path(args.env_file) if args.env_file else None, force=args.force)
    except FileExistsError as exc:
        print(tr(f"Erro: {exc}", f"Error: {exc}"), file=sys.stderr)
        return 2
    print(
        tr(
            f"Chave gerada e salva em {path} (permissão 0600). O servidor a lê sozinho ao iniciar.",
            f"Key generated and saved to {path} (0600 permissions). The server reads it on its own at startup.",
        )
    )
    print(f"ANHANGA_API_KEY={key}")
    print(
        tr(
            "Na interface, informe esta chave quando ela pedir; nas chamadas: 'Authorization: Bearer <chave>'.",
            "In the interface, enter this key when it asks; in API calls: 'Authorization: Bearer <key>'.",
        )
    )
    return 0


def _run_backup(args: argparse.Namespace) -> int:
    import os

    from anhanga.engine.config import find_config_path, load_config
    from anhanga.storage import backup_database

    src = args.db or os.getenv("ANHANGA_DB_PATH")
    if not src:
        src = load_config(find_config_path()).storage.path
    try:
        dest = backup_database(src, args.destination, force=args.force)
    except (OSError, ValueError, sqlite3.Error) as exc:  # banco travado/corrompido: erro claro, sem traceback
        print(tr(f"Erro no backup: {exc}", f"Backup error: {exc}"), file=sys.stderr)
        return 2
    print(tr(f"Backup de {src} gravado em {dest} (0600).", f"Backup of {src} written to {dest} (0600)."))
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    """Executa o servidor web e API do Anhangá via uvicorn."""
    import os

    import uvicorn

    from anhanga.envfile import load_dotenv

    load_dotenv()  # idempotente (o pacote já o carrega na importação); cobre um .env criado depois, ex.: `keygen` na mesma sessão
    if not _is_loopback_host(args.host) and not os.getenv("ANHANGA_API_KEY"):
        print(
            tr(
                f"Recusado: escutar em {args.host} (fora do loopback) exige chave da API. "
                "Rode 'anhanga keygen' (grava em .env) ou defina ANHANGA_API_KEY.",
                f"Refused: listening on {args.host} (outside loopback) requires an API key. "
                "Run 'anhanga keygen' (writes to .env) or set ANHANGA_API_KEY.",
            ),
            file=sys.stderr,
        )
        return 2

    try:
        uvicorn.run(
            "anhanga.main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            workers=1,  # instância única: cada worker rodaria o loop de monitoramento e alertaria em duplicidade
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(tr(f"Erro ao iniciar servidor Anhangá: {exc}", f"Error starting the Anhangá server: {exc}"), file=sys.stderr)
        return 1


async def async_main(argv: list[str] | None = None) -> int:
    """Versão assíncrona do entrypoint principal da CLI do Anhangá."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()

    try:
        if not raw_args:
            parser.print_help(sys.stderr)
            return 3

        parsed_args = parser.parse_args(raw_args)
        if parsed_args.command == "keygen":
            return _run_keygen(parsed_args)
        elif parsed_args.command == "backup":
            return _run_backup(parsed_args)
        elif parsed_args.command == "serve":
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _run_serve, parsed_args)
        elif parsed_args.command == "check":
            return await _run_check_async(parsed_args)
        else:
            parser.print_help(sys.stderr)
            return 3
    except CLIArgumentError as arg_err:
        print(tr(f"Erro de argumento: {arg_err}", f"Argument error: {arg_err}"), file=sys.stderr)
        return 3
    except SystemExit as sys_exit:
        code = sys_exit.code
        return int(code) if isinstance(code, int) else 0


def main(argv: list[str] | None = None) -> int:
    """Entrypoint principal da CLI do Anhangá."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()

    if not raw_args:
        parser.print_help(sys.stderr)
        return 3

    try:
        parsed_args = parser.parse_args(raw_args)
    except CLIArgumentError as arg_err:
        print(tr(f"Erro de argumento: {arg_err}", f"Argument error: {arg_err}"), file=sys.stderr)
        return 3
    except SystemExit as sys_exit:
        code = sys_exit.code
        return int(code) if isinstance(code, int) else 0

    if parsed_args.command == "keygen":
        return _run_keygen(parsed_args)
    elif parsed_args.command == "backup":
        return _run_backup(parsed_args)
    elif parsed_args.command == "serve":
        return _run_serve(parsed_args)
    elif parsed_args.command == "check":
        try:
            asyncio.get_running_loop()
            loop_running = True
        except RuntimeError:
            loop_running = False

        try:
            if loop_running:
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    return pool.submit(lambda: asyncio.run(_run_check_async(parsed_args))).result()
            return asyncio.run(_run_check_async(parsed_args))
        except CLIArgumentError as arg_err:
            print(tr(f"Erro de argumento: {arg_err}", f"Argument error: {arg_err}"), file=sys.stderr)
            return 3
    else:
        parser.print_help(sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
