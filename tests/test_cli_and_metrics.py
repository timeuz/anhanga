import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile

from fastapi.testclient import TestClient
import pytest

from anhanga.cli import (
    SARIF_SCHEMA_URI,
    build_sarif_report,
    evaluate_probe_gates,
    main,
    parse_duration_ms,
)
from anhanga.engine.models import (
    ProbeResult,
    SampleMeasurement,
    SamplingStats,
    SecurityAudit,
    SecurityFinding,
    TLSInspection,
    build_timing_breakdown,
)
from anhanga.engine.probe import SSRFBlockedError
from anhanga.engine.security import RATE_LIMITER
from anhanga.engine.webhooks import (
    build_slack_payload,
    build_teams_payload,
    build_telegram_payload,
    detect_webhook_provider,
    send_webhook_alert,
)
from anhanga.main import HISTORY_CACHE, STATE_CACHE, app
from anhanga.metrics.exporter import record_probe_metrics, render_prometheus_metrics

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_state():
    STATE_CACHE.clear()
    HISTORY_CACHE.clear()
    RATE_LIMITER.reset()


async def _local_http_handler(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    """
    Servidor HTTP local para testes de CLI e Webhooks:
    - GET /secure -> 200 OK com todos os headers de segurança (Nota A+) e ~20ms TTFB
    - GET /slow   -> 200 OK sem headers de segurança e ~120ms TTFB
    - GET /down   -> 503 Service Unavailable
    - POST /webhook -> 200 OK capturando JSON enviado
    """
    try:
        req_line = await reader.readline()
        if not req_line:
            return
        parts = req_line.decode("latin1").strip().split(" ")
        method = parts[0] if len(parts) > 0 else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        content_length = 0
        while True:
            line = await reader.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            decoded = line.decode("latin1").strip()
            if decoded.lower().startswith("content-length:"):
                content_length = int(decoded.split(":", 1)[1].strip())

        body_bytes = b""
        if content_length > 0:
            body_bytes = await reader.readexactly(content_length)

        if method == "POST" and path.startswith("/webhook"):
            _WEBHOOK_CAPTURED.append(json.loads(body_bytes.decode("utf-8")))
            resp = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 11\r\n"
                "Connection: close\r\n"
                "\r\n"
                '{"ok":true}'
            )
            writer.write(resp.encode("latin1"))
            await writer.drain()
            return

        if path.startswith("/down"):
            resp = (
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Length: 4\r\n"
                "Connection: close\r\n"
                "\r\n"
                "DOWN"
            )
            writer.write(resp.encode("latin1"))
            await writer.drain()
            return

        if path.startswith("/slow"):
            await asyncio.sleep(0.110)
            resp = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Length: 4\r\n"
                "Connection: close\r\n"
                "\r\n"
                "SLOW"
            )
            writer.write(resp.encode("latin1"))
            await writer.drain()
            return

        # Default /secure
        await asyncio.sleep(0.015)
        resp = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Length: 2\r\n"
            "Connection: close\r\n"
            "\r\n"
            "OK"
        )
        writer.write(resp.encode("latin1"))
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


_WEBHOOK_CAPTURED: list[dict] = []


def _make_sample_probe_result(
    is_up: bool = True,
    grade: str = "A+",
    score: int = 100,
    ttfb_ms: float = 45.0,
    error: str | None = None,
) -> ProbeResult:
    timings = build_timing_breakdown(
        dns_ms=12.0,
        tcp_ms=18.0,
        tls_ms=30.0,
        ttfb_ms=ttfb_ms,
        transfer_ms=10.0,
    )
    s1 = SampleMeasurement(
        sample_index=1,
        connection_reused=False,
        status_code=200 if is_up else 503,
        timings=timings,
    )
    warm_timings = build_timing_breakdown(
        dns_ms=0.0,
        tcp_ms=0.0,
        tls_ms=0.0,
        ttfb_ms=ttfb_ms,
        transfer_ms=8.0,
    )
    s2 = SampleMeasurement(
        sample_index=2,
        connection_reused=True,
        status_code=200 if is_up else 503,
        timings=warm_timings,
    )
    sampling = SamplingStats(
        samples_count=2,
        cold_total_ms=timings.total_ms,
        warm_avg_total_ms=warm_timings.total_ms,
        p50_ms=round((timings.total_ms + warm_timings.total_ms) / 2, 2),
        p95_ms=timings.total_ms,
        p99_ms=timings.total_ms,
        min_ms=warm_timings.total_ms,
        max_ms=timings.total_ms,
        mean_ms=round((timings.total_ms + warm_timings.total_ms) / 2, 2),
        jitter_ms=round(abs(timings.total_ms - warm_timings.total_ms), 2),
        raw_samples=[s1, s2],
    )
    findings = []
    if grade in ("C", "D", "F"):
        findings.append(
            SecurityFinding(
                id="SEC-HSTS",
                header="Strict-Transport-Security",
                category="header",
                severity="high",
                weight=25,
                description="HSTS ausente no endpoint HTTPS.",
                remediation='add_header Strict-Transport-Security "max-age=2592000; includeSubDomains" always;',
            )
        )

    expires_dt = datetime(2027, 1, 15, 0, 0, 0, tzinfo=timezone.utc)
    return ProbeResult(
        target_url="https://edge.example.com",
        final_url="https://edge.example.com/",
        resolved_ip="93.184.216.34",
        is_up=is_up,
        http_version="HTTP/2",
        status_code=200 if is_up else 503,
        redirect_hops=1,
        timings=timings,
        sampling=sampling,
        tls=TLSInspection(
            valid=True,
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            issuer="Let's Encrypt",
            subject="edge.example.com",
            expires_at=expires_dt,
            days_remaining=60,
            alert_expiring=False,
        ),
        security=SecurityAudit(
            grade=grade,  # type: ignore[arg-type]
            score=score,
            missing_findings=findings,
        ),
        error=error,
    )


def test_parse_duration_ms():
    """Valida o parser de duração aceitando ms, s, números puros e rejeitando formatos inválidos."""
    assert parse_duration_ms("500ms") == 500.0
    assert parse_duration_ms("0.5s") == 500.0
    assert parse_duration_ms("1.5s") == 1500.0
    assert parse_duration_ms("250") == 250.0
    assert parse_duration_ms(300) == 300.0

    with pytest.raises(ValueError):
        parse_duration_ms("")
    with pytest.raises(ValueError):
        parse_duration_ms("-100ms")
    with pytest.raises(ValueError):
        parse_duration_ms("invalid")


def test_evaluate_probe_gates_exit_codes():
    """Valida a lógica de Quality Gates e os exit codes padronizados (0, 1 e 2)."""
    # Caso 0: Aprovado em todos os gates
    res_ok = _make_sample_probe_result(is_up=True, grade="A", score=90, ttfb_ms=45.0)
    passed, code, violations = evaluate_probe_gates(
        res_ok, min_grade="B", max_ttfb_ms=500.0, max_total_ms=1000.0
    )
    assert passed is True
    assert code == 0
    assert violations == []

    # Caso 1: Violação de --min-grade e --max-ttfb -> exit code 1
    res_slow_bad_grade = _make_sample_probe_result(
        is_up=True, grade="D", score=35, ttfb_ms=620.0
    )
    passed, code, violations = evaluate_probe_gates(
        res_slow_bad_grade, min_grade="B", max_ttfb_ms=500.0
    )
    assert passed is False
    assert code == 1
    assert len(violations) == 2
    assert any("Nota de segurança insuficiente" in v for v in violations)
    assert any("SLO de TTFB violado" in v for v in violations)

    # Caso 1b: Alvo offline -> exit code 1
    res_down = _make_sample_probe_result(is_up=False, grade="F", score=0)
    passed, code, violations = evaluate_probe_gates(res_down)
    assert passed is False
    assert code == 1
    assert any("OFFLINE" in v for v in violations)

    # Caso 2: Bloqueio Anti-SSRF ou erro de DNS -> exit code 2
    res_ssrf = _make_sample_probe_result(
        is_up=False,
        error="Bloqueado pelo Guardião Anti-SSRF: IP privado/restrito (127.0.0.1).",
    )
    passed, code, violations = evaluate_probe_gates(res_ssrf)
    assert passed is False
    assert code == 2
    assert any("Anti-SSRF" in v for v in violations)


class _BackgroundTestServer:
    """Roda o servidor asyncio de teste em uma thread dedicada para permitir chamadas síncronas da CLI e TestClient."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.port: int = 0
        self._server: asyncio.AbstractServer | None = None
        self._thread: concurrent.futures.Future | None = None
        import threading

        self._ready = threading.Event()
        self._worker = threading.Thread(target=self._run_loop, daemon=True)

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self._server = self.loop.run_until_complete(
            asyncio.start_server(_local_http_handler, "127.0.0.1", 0)
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        self.loop.run_forever()

    def __enter__(self) -> "_BackgroundTestServer":
        self._worker.start()
        self._ready.wait(timeout=5.0)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._server is not None:
            self.loop.call_soon_threadsafe(self._server.close)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._worker.join(timeout=5.0)
        self.loop.close()


def test_cli_check_exit_codes_and_json_sarif_outputs(capsys):
    """Testa a CLI `anhanga check` ponta a ponta com servidor local e valida JSON, Rich e SARIF v2.1.0."""
    with _BackgroundTestServer() as srv:
        port = srv.port

        # 1. Exit code 2 quando IPs privados são bloqueados pelo Anti-SSRF (sem --allow-private)
        code_ssrf = main(
            ["check", f"http://127.0.0.1:{port}/secure", "--format", "json"]
        )
        captured_ssrf = capsys.readouterr()
        assert code_ssrf == 2
        ssrf_json = json.loads(captured_ssrf.out)
        assert ssrf_json["passed"] is False
        assert ssrf_json["exit_code"] == 2
        assert any("Anti-SSRF" in v for v in ssrf_json["violations"])

        # 2. Exit code 2 para argumentos inválidos
        code_bad_arg = main(
            ["check", f"http://127.0.0.1:{port}/secure", "--max-ttfb", "invalid_ms"]
        )
        capsys.readouterr()
        assert code_bad_arg == 2

        # 3. Exit code 0 quando os limites de TTFB e Grade passam + envio de webhook via CLI
        _WEBHOOK_CAPTURED.clear()
        with tempfile.TemporaryDirectory() as tmpdir:
            json_out_file = Path(tmpdir) / "report.json"
            code_ok = main(
                [
                    "check",
                    "--url",
                    f"http://127.0.0.1:{port}/secure",
                    "--allow-private",
                    "--min-grade",
                    "F",
                    "--max-ttfb",
                    "500ms",
                    "--max-total",
                    "1.5s",
                    "--webhook-url",
                    f"http://127.0.0.1:{port}/webhook",
                    "--webhook-provider",
                    "slack",
                    "--format",
                    "json",
                    "--output",
                    str(json_out_file),
                ]
            )
            captured_ok = capsys.readouterr()
            assert code_ok == 0
            data_ok = json.loads(captured_ok.out)
            assert data_ok["passed"] is True
            assert data_ok["exit_code"] == 0
            assert data_ok["violations"] == []
            assert data_ok["thresholds"]["max_ttfb_ms"] == 500.0
            assert data_ok["thresholds"]["max_total_ms"] == 1500.0
            assert json_out_file.exists()
            assert len(_WEBHOOK_CAPTURED) == 1
            assert "blocks" in _WEBHOOK_CAPTURED[0]

            # 4. Exit code 1 quando --min-grade B ou --max-ttfb 50ms falham + validação SARIF v2.1.0
            sarif_out_file = Path(tmpdir) / "report.sarif"
            code_fail = main(
                [
                    "check",
                    f"http://127.0.0.1:{port}/slow",
                    "--allow-private",
                    "--min-grade",
                    "B",
                    "--max-ttfb",
                    "50ms",
                    "--format",
                    "sarif",
                    "--output",
                    str(sarif_out_file),
                ]
            )
            captured_sarif = capsys.readouterr()
            assert code_fail == 1
            sarif_doc = json.loads(captured_sarif.out)
            assert sarif_doc["version"] == "2.1.0"
            assert sarif_doc["$schema"] == SARIF_SCHEMA_URI
            assert len(sarif_doc["runs"]) == 1

            run0 = sarif_doc["runs"][0]
            assert run0["tool"]["driver"]["name"] == "Anhangá"
            assert len(run0["tool"]["driver"]["rules"]) >= 2
            assert len(run0["results"]) >= 2

            rule_ids = {r["ruleId"] for r in run0["results"]}
            assert "ANHANGA-SLO-TTFB" in rule_ids
            assert "ANHANGA-GATE-SECURITY-GRADE" in rule_ids
            for item in run0["results"]:
                assert "level" in item
                assert "text" in item["message"]
                uri = item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                assert f"127.0.0.1:{port}" in uri

            # 5. Saída Rich (text) e /probe endpoint
            code_text = main(
                [
                    "check",
                    f"http://127.0.0.1:{port}/secure",
                    "--allow-private",
                    "--format",
                    "text",
                ]
            )
            captured_text = capsys.readouterr()
            assert code_text == 0
            assert "QUALITY GATES APROVADOS" in captured_text.out

            probe_resp = client.get(
                f"/probe?target=http://127.0.0.1:{port}/secure&allow_private=true&samples=2"
            )
            assert probe_resp.status_code == 200
            assert "probe_http_duration_seconds" in probe_resp.text
            assert 'phase="resolve"' in probe_resp.text
            assert 'phase="connect"' in probe_resp.text
            assert 'phase="processing"' in probe_resp.text
            assert 'phase="transfer"' in probe_resp.text


def test_prometheus_blackbox_exporter_and_extended_metrics():
    """
    Valida que /metrics e /probe expõem todas as séries em segundos compatíveis com
    blackbox_exporter (`probe_http_duration_seconds{phase="resolve|connect|tls|processing|transfer"}`)
    e a série estendida do Anhangá (quantis P50/P95/P99, jitter, cold/warm).
    """
    sample = _make_sample_probe_result(is_up=True, grade="A+", score=100, ttfb_ms=45.0)
    record_probe_metrics(sample)

    resp = client.get("/metrics")
    assert resp.status_code == 200
    body = resp.text

    # 1. Série compatível com blackbox_exporter em segundos
    assert 'probe_success{instance="edge.example.com",target="https://edge.example.com"} 1.0' in body
    # total_ms = 12 + 18 + 30 + 45 + 10 = 115ms -> 0.115s
    assert 'probe_duration_seconds{instance="edge.example.com",target="https://edge.example.com"} 0.115' in body
    assert 'probe_http_duration_seconds{instance="edge.example.com",phase="resolve",target="https://edge.example.com"} 0.012' in body
    assert 'probe_http_duration_seconds{instance="edge.example.com",phase="connect",target="https://edge.example.com"} 0.018' in body
    assert 'probe_http_duration_seconds{instance="edge.example.com",phase="tls",target="https://edge.example.com"} 0.03' in body
    assert 'probe_http_duration_seconds{instance="edge.example.com",phase="processing",target="https://edge.example.com"} 0.045' in body
    assert 'probe_http_duration_seconds{instance="edge.example.com",phase="transfer",target="https://edge.example.com"} 0.01' in body
    assert 'probe_http_status_code{instance="edge.example.com",target="https://edge.example.com"} 200.0' in body
    assert 'probe_http_redirects{instance="edge.example.com",target="https://edge.example.com"} 1.0' in body
    assert 'probe_http_ssl{instance="edge.example.com",target="https://edge.example.com"} 1.0' in body
    assert 'probe_http_version{instance="edge.example.com",target="https://edge.example.com"} 2.0' in body
    assert 'probe_ssl_earliest_cert_expiry{instance="edge.example.com",target="https://edge.example.com"}' in body

    # 2. Série estendida do Anhangá em segundos
    assert 'anhanga_probe_up{target="https://edge.example.com"} 1.0' in body
    assert 'anhanga_probe_duration_seconds{phase="dns",target="https://edge.example.com"} 0.012' in body
    assert 'anhanga_probe_duration_seconds{phase="resolve",target="https://edge.example.com"} 0.012' in body
    assert 'anhanga_probe_duration_seconds{phase="connect",target="https://edge.example.com"} 0.018' in body
    assert 'anhanga_probe_duration_seconds{phase="processing",target="https://edge.example.com"} 0.045' in body
    assert 'anhanga_probe_latency_quantile_seconds{quantile="0.5",target="https://edge.example.com"}' in body
    assert 'anhanga_probe_latency_quantile_seconds{quantile="0.95",target="https://edge.example.com"} 0.115' in body
    assert 'anhanga_probe_latency_quantile_seconds{quantile="0.99",target="https://edge.example.com"} 0.115' in body
    assert 'anhanga_probe_jitter_seconds{target="https://edge.example.com"}' in body
    assert 'anhanga_probe_connection_cold_seconds{target="https://edge.example.com"} 0.115' in body
    assert 'anhanga_probe_connection_warm_seconds{target="https://edge.example.com"} 0.053' in body
    assert 'anhanga_probe_security_score{grade="A+",target="https://edge.example.com"} 100.0' in body


def test_webhook_payload_builders_and_ssrf_protection():
    """Valida a construção de payloads para Slack, Teams e Telegram, envio HTTP e bloqueio Anti-SSRF."""
    sample = _make_sample_probe_result(is_up=False, grade="D", score=40, ttfb_ms=610.0)
    violations = ["SLO de TTFB violado: 610.00ms > 500.00ms"]

    # Detecção automática de provedor
    assert detect_webhook_provider("https://hooks.slack.com/services/T00/B00/X00") == "slack"
    assert detect_webhook_provider("https://outlook.office.com/webhook/123") == "teams"
    assert detect_webhook_provider("https://api.telegram.org/bot123:ABC/sendMessage") == "telegram"

    # Slack payload
    slack_payload = build_slack_payload(sample, violations=violations)
    assert "blocks" in slack_payload
    assert "attachments" in slack_payload
    assert slack_payload["attachments"][0]["color"] == "#ef4444"
    assert "610.00ms" in json.dumps(slack_payload, ensure_ascii=False)

    # Microsoft Teams payload
    teams_payload = build_teams_payload(sample, violations=violations)
    assert teams_payload["@type"] == "MessageCard"
    assert teams_payload["themeColor"] == "EF4444"
    fact_names = [f["name"] for f in teams_payload["sections"][0]["facts"]]
    assert "Latência Total" in fact_names
    assert "TTFB" in fact_names
    assert "Nota de Segurança" in fact_names
    assert "Status TLS" in fact_names

    # Telegram payload
    tg_payload = build_telegram_payload(
        sample, violations=violations, chat_id="-100999888"
    )
    assert tg_payload["chat_id"] == "-100999888"
    assert tg_payload["parse_mode"] == "HTML"
    assert tg_payload["disable_web_page_preview"] is True
    assert "edge.example.com" in tg_payload["text"]

    # Bloqueio Anti-SSRF em URL de webhook apontando para IP privado quando allow_private=False
    async def _check_ssrf_and_delivery():
        with pytest.raises(SSRFBlockedError):
            await send_webhook_alert(
                webhook_url="http://127.0.0.1:9999/webhook",
                result=sample,
                allow_private=False,
            )

        # Envio real para servidor local quando allow_private=True
        _WEBHOOK_CAPTURED.clear()
        server = await asyncio.start_server(_local_http_handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            wh_url = f"http://127.0.0.1:{port}/webhook"
            delivery = await send_webhook_alert(
                webhook_url=wh_url,
                result=sample,
                provider="teams",
                violations=violations,
                allow_private=True,
            )
            assert delivery["sent"] is True
            assert delivery["status_code"] == 200
            assert delivery["provider"] == "teams"
            assert len(_WEBHOOK_CAPTURED) == 1
            assert _WEBHOOK_CAPTURED[0]["@type"] == "MessageCard"
        finally:
            server.close()
            await server.wait_closed()

    asyncio.run(_check_ssrf_and_delivery())

    # Valida também o bloqueio Anti-SSRF via endpoint POST /api/v1/webhooks/notify
    api_resp = client.post(
        "/api/v1/webhooks/notify",
        json={
            "webhook_url": "http://169.254.169.254/latest/meta-data/",
            "result": sample.model_dump(mode="json"),
            "allow_private": False,
        },
    )
    assert api_resp.status_code == 403
    assert "Anti-SSRF" in api_resp.json()["detail"]
