import argparse
import asyncio
import concurrent.futures
import json
from pathlib import Path
import re
import sys
from typing import Any, NoReturn

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from anhanga.engine.models import ProbeResult
from anhanga.engine.probe import execute_probe
from anhanga.engine.webhooks import send_webhook_alert

GRADE_RANK: dict[str, int] = {
    "A+": 6,
    "A": 5,
    "B": 4,
    "C": 3,
    "D": 2,
    "F": 1,
}

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"


class CLIArgumentError(ValueError):
    """Exceção interna para argumentos inválidos na CLI (exit code 2)."""


class _NonExitingArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise CLIArgumentError(message)


def parse_duration_ms(val: str | int | float) -> float:
    """
    Converte strings de duração ('500ms', '0.5s', '1.5s', '250') para milissegundos (float).
    Levanta ValueError se o formato for inválido ou <= 0.
    """
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        fval = float(val)
        if fval <= 0:
            raise ValueError(f"Duração deve ser maior que zero: {val}")
        return round(fval, 2)

    if not isinstance(val, str):
        raise ValueError(f"Formato de duração inválido: {val!r}")

    raw = val.strip().lower()
    if not raw:
        raise ValueError("Formato de duração vazio.")

    m = re.match(r"^([+-]?\d+(?:\.\d+)?)\s*(ms|s|m)?$", raw)
    if not m:
        raise ValueError(f"Formato de duração inválido: '{val}'. Use ex: '500ms', '0.5s' ou '500'.")

    number = float(m.group(1))
    unit = m.group(2) or "ms"
    if number <= 0:
        raise ValueError(f"Duração deve ser positiva: '{val}'.")

    if unit == "ms":
        return round(number, 2)
    if unit == "s":
        return round(number * 1000.0, 2)
    if unit == "m":
        return round(number * 60_000.0, 2)
    raise ValueError(f"Unidade de duração desconhecida: '{unit}'.")


def _is_execution_or_ssrf_error(error_msg: str | None) -> bool:
    """Identifica se o erro foi bloqueio Anti-SSRF, falha de DNS ou URL inválida (exit code 2)."""
    if not error_msg:
        return False
    lower = error_msg.lower()
    return any(
        token in lower
        for token in (
            "anti-ssrf",
            "erro de dns",
            "url inválida",
            "esquema",
            "hostname não encontrado",
        )
    )


def evaluate_probe_gates(
    result: ProbeResult,
    min_grade: str | None = None,
    max_ttfb_ms: float | None = None,
    max_total_ms: float | None = None,
) -> tuple[bool, int, list[str]]:
    """
    Avalia os Quality Gates de SRE/DevSecOps sobre um ProbeResult.
    Retorna (passed, exit_code, violations):
    - exit_code 2: Erro de DNS, bloqueio Anti-SSRF ou URL inválida
    - exit_code 1: Alvo offline ou violação de --min-grade, --max-ttfb ou --max-total
    - exit_code 0: Todas as verificações passaram
    """
    violations: list[str] = []

    if _is_execution_or_ssrf_error(result.error):
        violations.append(result.error or "Erro de DNS ou bloqueio Anti-SSRF.")
        return False, 2, violations

    if not result.is_up:
        reason = result.error or f"HTTP {result.status_code or 'ERR'}"
        violations.append(f"Alvo OFFLINE: {reason}")

    if min_grade:
        norm_min = min_grade.strip().upper()
        if norm_min not in GRADE_RANK:
            raise CLIArgumentError(
                f"Nota mínima inválida '{min_grade}'. Escolha entre: {', '.join(GRADE_RANK.keys())}."
            )
        actual_grade = (result.security.grade or "F").upper()
        if GRADE_RANK.get(actual_grade, 1) < GRADE_RANK[norm_min]:
            violations.append(
                f"Nota de segurança insuficiente: obtido '{actual_grade}' (score {result.security.score}/100), mínimo exigido '{norm_min}'."
            )

    if max_ttfb_ms is not None and result.timings.ttfb_ms > max_ttfb_ms:
        violations.append(
            f"SLO de TTFB violado: {result.timings.ttfb_ms:.2f}ms excede o limite de {max_ttfb_ms:.2f}ms."
        )

    if max_total_ms is not None and result.timings.total_ms > max_total_ms:
        violations.append(
            f"SLO de Latência Total violado: {result.timings.total_ms:.2f}ms excede o limite de {max_total_ms:.2f}ms."
        )

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

    # 1. Violações de Quality Gates (SLO, Grade, Disponibilidade, Anti-SSRF)
    for idx, violation in enumerate(violations, start=1):
        v_lower = violation.lower()
        if "anti-ssrf" in v_lower or "dns" in v_lower:
            rule_id = "ANHANGA-SSRF-OR-DNS"
            rule_name = "SSRFOrDNSValidationFailure"
            short_desc = "Bloqueio Anti-SSRF ou falha de resolução DNS"
        elif "ttfb" in v_lower:
            rule_id = "ANHANGA-SLO-TTFB"
            rule_name = "TTFBSLOViolation"
            short_desc = "Violação de SLO de Time to First Byte (TTFB)"
        elif "latência total" in v_lower or "total" in v_lower:
            rule_id = "ANHANGA-SLO-TOTAL"
            rule_name = "TotalLatencySLOViolation"
            short_desc = "Violação de SLO de Latência Total"
        elif "nota de segurança" in v_lower or "grade" in v_lower:
            rule_id = "ANHANGA-GATE-SECURITY-GRADE"
            rule_name = "MinimumSecurityGradeViolation"
            short_desc = "Nota de segurança abaixo do mínimo exigido pelo Quality Gate"
        elif "offline" in v_lower:
            rule_id = "ANHANGA-AVAILABILITY"
            rule_name = "TargetUnavailable"
            short_desc = "Alvo indisponível ou retornando erro HTTP"
        else:
            rule_id = f"ANHANGA-GATE-{idx}"
            rule_name = f"QualityGateViolation{idx}"
            short_desc = "Violação de Quality Gate na auditoria"

        _ensure_rule(
            rule_id=rule_id,
            name=rule_name,
            short_desc=short_desc,
            full_desc=violation,
            help_text="Verifique a disponibilidade, latência de borda e cabeçalhos de segurança do endpoint.",
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

    # 2. Achados de Segurança DevSecOps (missing_findings)
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
                    "text": f"[{finding.header}] {finding.description} | Remediação: {finding.remediation}"
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
                        "version": "0.1.0",
                        "informationUri": "https://github.com/timeuz/anhanga",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": exit_code != 2,
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


def render_rich_report(
    result: ProbeResult,
    violations: list[str],
    exit_code: int,
    thresholds: dict[str, Any],
) -> str:
    """Renderiza relatório tático com Rich para exibição no terminal e retorna versão em texto."""
    console = Console(record=True, width=100)

    status_badge = (
        f"[bold green]ONLINE (HTTP {result.status_code})[/bold green]"
        if result.is_up
        else f"[bold red]OFFLINE ({result.error or result.status_code or 'ERR'})[/bold red]"
    )
    grade = result.security.grade
    grade_color = (
        "green"
        if grade in ("A+", "A")
        else ("yellow" if grade in ("B", "C") else "red")
    )

    header_text = Text.from_markup(
        f"[bold orange1]🔥 ANHANGÁ — AUDITORIA SRE & DEVSECOPS[/bold orange1]\n"
        f"Alvo: [bold cyan]{result.target_url}[/bold cyan]  |  "
        f"IP: [bold]{result.resolved_ip or 'N/A'}[/bold]  |  "
        f"Status: {status_badge}  |  "
        f"Nota: [bold {grade_color}]{grade} ({result.security.score}/100)[/bold {grade_color}]"
    )
    console.print(Panel(header_text, border_style="orange1"))

    # Tabela Waterfall de Decomposição de Latência
    wf_table = Table(
        title="Waterfall de Latência Não-Cumulativa (ms)",
        show_header=True,
        header_style="bold cyan",
    )
    wf_table.add_column("Fase", style="bold")
    wf_table.add_column("Janela (start → end)", justify="right")
    wf_table.add_column("Duração (ms)", justify="right")
    wf_table.add_column("Status SLO", justify="center")
    wf_table.add_column("Gargalo", justify="center")

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
            "🔥 SIM" if p.is_dominant else "-",
        )
    wf_table.add_row(
        "[bold]TOTAL[/bold]",
        f"0.00 → {result.timings.total_ms:.2f} ms",
        f"[bold]{result.timings.total_ms:.2f} ms[/bold]",
        "-",
        f"Dominante: {result.timings.dominant_phase or 'N/A'}",
    )
    console.print(wf_table)

    # Estatísticas de Amostragem (P50 / P95 / P99 / Jitter / Fria vs Keep-Alive)
    samp = result.sampling
    warm_str = (
        f"{samp.warm_avg_total_ms:.2f} ms"
        if samp.warm_avg_total_ms is not None
        else "N/A (1 amostra)"
    )
    stats_panel = Panel(
        f"Amostras: [bold]{samp.samples_count}x[/bold]  |  "
        f"P50: [bold]{samp.p50_ms:.2f} ms[/bold]  |  "
        f"P95: [bold]{samp.p95_ms:.2f} ms[/bold]  |  "
        f"P99: [bold]{samp.p99_ms:.2f} ms[/bold]  |  "
        f"Jitter: [bold]{samp.jitter_ms:.2f} ms[/bold]\n"
        f"Conexão Fria (1ª): [bold]{samp.cold_total_ms:.2f} ms[/bold]  |  "
        f"Keep-Alive (Reaproveitada): [bold]{warm_str}[/bold]",
        title="Estatísticas SRE (Percentis & Reuso de Conexão)",
        border_style="blue",
    )
    console.print(stats_panel)

    # Resumo TLS
    if result.tls:
        tls_valid_str = (
            "[bold green]VÁLIDO[/bold green]"
            if result.tls.valid
            else "[bold red]INVÁLIDO[/bold red]"
        )
        console.print(
            Panel(
                f"Certificado: {tls_valid_str}  |  Protocolo: [bold]{result.tls.protocol or 'N/A'}[/bold]  |  "
                f"Cifra: [bold]{result.tls.cipher or 'N/A'}[/bold]\n"
                f"Emissor: {result.tls.issuer or 'N/A'}  |  "
                f"Dias Restantes: [bold]{result.tls.days_remaining if result.tls.days_remaining is not None else 'N/A'}[/bold]  |  "
                f"OCSP: {result.tls.ocsp_status}",
                title="Inspeção de Certificado TLS",
                border_style="cyan",
            )
        )

    # Resultado dos Quality Gates
    if exit_code == 0:
        console.print(
            Panel(
                "[bold green]✅ QUALITY GATES APROVADOS (Exit Code 0)[/bold green]",
                border_style="green",
            )
        )
    else:
        v_lines = "\n".join(f"• [bold red]{v}[/bold red]" for v in violations)
        console.print(
            Panel(
                f"[bold red]❌ FALHA NOS QUALITY GATES (Exit Code {exit_code})[/bold red]\n{v_lines}",
                title=f"Violações Detectadas ({len(violations)})",
                border_style="red",
            )
        )

    return console.export_text()


def _build_parser() -> _NonExitingArgumentParser:
    parser = _NonExitingArgumentParser(
        prog="anhanga",
        description="Anhangá — Auditor Tático de Borda, TLS, Latência e DevSecOps para SRE e CI/CD",
    )
    subparsers = parser.add_subparsers(dest="command")

    check_parser = subparsers.add_parser(
        "check",
        help="Executa auditoria com Quality Gates de SLO e DevSecOps para pipelines CI/CD",
    )
    check_parser.add_argument(
        "target_positional",
        nargs="?",
        default=None,
        help="URL ou hostname alvo para auditoria",
    )
    check_parser.add_argument(
        "--url",
        "-u",
        dest="target_option",
        default=None,
        help="URL ou hostname alvo para auditoria",
    )
    check_parser.add_argument(
        "--min-grade",
        default=None,
        help="Nota mínima de segurança exigida (A+, A, B, C, D, F)",
    )
    check_parser.add_argument(
        "--max-ttfb",
        default=None,
        help="Limite máximo de TTFB (ex: 500ms, 0.5s ou 500)",
    )
    check_parser.add_argument(
        "--max-total",
        default=None,
        help="Limite máximo de Latência Total (ex: 1000ms, 1.5s ou 1000)",
    )
    check_parser.add_argument(
        "--samples",
        "-n",
        type=int,
        default=1,
        help="Quantidade de amostras para cálculo de P50/P95/P99 e Jitter (default: 1)",
    )
    check_parser.add_argument(
        "--timeout",
        "-t",
        type=float,
        default=5.0,
        help="Timeout por requisição em segundos (default: 5.0)",
    )
    check_parser.add_argument(
        "--allow-private",
        action="store_true",
        default=False,
        help="Permite sondar IPs de rede interna / loopback (ambientes de Lab/CI local)",
    )
    check_parser.add_argument(
        "--format",
        "-f",
        choices=("text", "json", "sarif"),
        default="text",
        help="Formato do relatório de saída: text, json ou sarif (default: text)",
    )
    check_parser.add_argument(
        "--output",
        "-o",
        default=None,
        help="Caminho opcional de arquivo para salvar o relatório gerado",
    )
    check_parser.add_argument(
        "--webhook-url",
        default=None,
        help="URL opcional de Webhook (Slack, Microsoft Teams ou Telegram) para envio de alerta",
    )
    check_parser.add_argument(
        "--webhook-provider",
        choices=("auto", "slack", "teams", "telegram"),
        default="auto",
        help="Provedor de Webhook (default: auto)",
    )
    check_parser.add_argument(
        "--telegram-chat-id",
        default=None,
        help="Chat ID opcional para alertas via Telegram Bot API",
    )

    serve_parser = subparsers.add_parser(
        "serve",
        help="Inicia o servidor Web e a API FastAPI do Anhangá",
    )
    serve_parser.add_argument(
        "--host",
        "-H",
        default="127.0.0.1",
        help="Endereço IP/host de escuta do servidor (default: 127.0.0.1)",
    )
    serve_parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=7890,
        help="Porta TCP do servidor (default: 7890)",
    )
    serve_parser.add_argument(
        "--reload",
        action="store_true",
        default=False,
        help="Ativa hot-reload automático para desenvolvimento",
    )
    serve_parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=1,
        help="Quantidade de processos workers (default: 1)",
    )
    return parser


async def _run_check_async(args: argparse.Namespace) -> int:
    target_url = (args.target_option or args.target_positional or "").strip()
    if not target_url:
        raise CLIArgumentError("URL alvo obrigatória. Informe posicionalmente ou via --url.")

    if args.samples < 1 or args.samples > 50:
        raise CLIArgumentError("--samples deve estar entre 1 e 50.")
    if args.timeout <= 0:
        raise CLIArgumentError("--timeout deve ser maior que zero.")

    min_grade: str | None = None
    if args.min_grade is not None:
        min_grade = args.min_grade.strip().upper()
        if min_grade not in GRADE_RANK:
            raise CLIArgumentError(
                f"Nota mínima inválida '{args.min_grade}'. Valores aceitos: {', '.join(GRADE_RANK.keys())}."
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
    )

    thresholds = {
        "min_grade": min_grade,
        "max_ttfb_ms": max_ttfb_ms,
        "max_total_ms": max_total_ms,
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


def _run_serve(args: argparse.Namespace) -> int:
    """Executa o servidor web e API do Anhangá via uvicorn."""
    import uvicorn

    try:
        uvicorn.run(
            "anhanga.main:app",
            host=args.host,
            port=args.port,
            reload=args.reload,
            workers=args.workers if not args.reload else None,
        )
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"Erro ao iniciar servidor Anhangá: {exc}", file=sys.stderr)
        return 1


async def async_main(argv: list[str] | None = None) -> int:
    """Versão assíncrona do entrypoint principal da CLI do Anhangá."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()

    try:
        if not raw_args:
            parser.print_help(sys.stderr)
            return 2

        parsed_args = parser.parse_args(raw_args)
        if parsed_args.command == "serve":
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _run_serve, parsed_args)
        elif parsed_args.command == "check":
            return await _run_check_async(parsed_args)
        else:
            parser.print_help(sys.stderr)
            return 2
    except CLIArgumentError as arg_err:
        print(f"Erro de argumento: {arg_err}", file=sys.stderr)
        return 2
    except SystemExit as sys_exit:
        code = sys_exit.code
        return int(code) if isinstance(code, int) else 0


def main(argv: list[str] | None = None) -> int:
    """Entrypoint principal da CLI do Anhangá."""
    raw_args = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()

    if not raw_args:
        parser.print_help(sys.stderr)
        return 2

    try:
        parsed_args = parser.parse_args(raw_args)
    except CLIArgumentError as arg_err:
        print(f"Erro de argumento: {arg_err}", file=sys.stderr)
        return 2
    except SystemExit as sys_exit:
        code = sys_exit.code
        return int(code) if isinstance(code, int) else 0

    if parsed_args.command == "serve":
        return _run_serve(parsed_args)
    elif parsed_args.command == "check":
        try:
            asyncio.get_running_loop()
            loop_running = True
        except RuntimeError:
            loop_running = False

        if loop_running:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(lambda: asyncio.run(_run_check_async(parsed_args))).result()
        return asyncio.run(_run_check_async(parsed_args))
    else:
        parser.print_help(sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
