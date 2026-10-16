from fastapi.testclient import TestClient

from anhanga.engine.models import (
    ProbeResult,
    SecurityAudit,
    TLSInspection,
    build_timing_breakdown,
)
from anhanga.main import HISTORY_CACHE, STATE_CACHE, _update_state_and_history, app


client = TestClient(app)


def setup_function():
    STATE_CACHE.clear()
    HISTORY_CACHE.clear()


def test_dashboard_renders_phase3_hero_kpis_and_i18n_pt_br():
    """Garante que o dashboard renderiza os Hero KPIs, seletor de amostras, tipografia e i18n PT-BR."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # 1. Color scheme dark, font-sans na prosa e font-mono para telemetria/código
    assert 'lang="pt-BR"' in html
    assert "color-scheme: dark" in html
    assert "font-sans" in html
    assert "font-mono" in html

    # 2. Padronização em Português do Brasil (PT-BR) + suporte i18n (pt-BR / en-US)
    assert "Auditor Tático de Borda, TLS, Latência e DevSecOps" in html
    assert "Nota de Segurança da Borda" in html
    assert "Latência Total de Ponta a Ponta" in html
    assert "Vigilância Contínua" in html
    assert "ONLINE" in html
    assert "OFFLINE" in html
    assert "I18N_DICTIONARY" in html
    assert "'pt-BR'" in html
    assert "'en-US'" in html

    # 3. Seletor de amostras no formulário (1x, 3x, 5x, 10x)
    assert 'id="samples-select"' in html
    assert 'value="1"' in html
    assert 'value="3"' in html
    assert 'value="5"' in html
    assert 'value="10"' in html


def test_dashboard_contains_tactical_waterfall_offsets_tls_and_redirect_chain():
    """Verifica o Waterfall tático real com offsets, SLOs, Fase Dominante, Redirects e Card TLS completo."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Waterfall com offsets reais (margin-left + width) e janela start_ms -> end_ms
    assert "getWaterfallBarStyle(phase)" in html
    assert "margin-left:" in html
    assert "phase.start_ms" in html
    assert "phase.end_ms" in html
    assert "phase.duration_ms" in html

    # Limiares de SLO (Saudável, Atenção, Crítico) e Fase Dominante
    assert "Saudável (OK)" in html
    assert "Atenção (Alerta)" in html
    assert "Crítico (Violação)" in html
    assert "Fase Dominante / Gargalo" in html
    assert "phase.is_dominant" in html

    # Estatísticas de Amostragem (P50, P95, P99, Jitter, Conexão Fria vs Keep-Alive)
    assert "P50 (Mediana)" in html
    assert "P95 (Cauda)" in html
    assert "P99 (Extremo)" in html
    assert "Jitter (Variação)" in html
    assert "Conexão Fria" in html
    assert "Keep-Alive (Reaproveitada)" in html

    # Rastreamento de Cadeia de Redirecionamentos (Hop-by-Hop)
    assert "Rastreamento de Cadeia de Redirecionamentos" in html
    assert "result?.redirect_chain" in html
    assert "hop.status_code" in html
    assert "hop.resolved_ip" in html

    # Card Completo de Certificado TLS
    assert "Inspeção Profunda de Certificado TLS" in html
    assert "result.tls.days_remaining" in html
    assert "result.tls.alert_expiring" in html
    assert "result.tls.issuer" in html
    assert "result.tls.subject" in html
    assert "result.tls.protocol" in html
    assert "result.tls.cipher" in html
    assert "result.tls.ocsp_status" in html
    assert "result.tls.tls10_11_accepted" in html
    assert "result.tls.cert_chain" in html
    assert "result.tls.sans" in html
    assert "result.tls.fingerprint_sha256" in html


def test_dashboard_runbook_multiserver_tabs_grade_simulation_and_rescan_delta():
    """Verifica as abas multi-servidor, cópia de snippet, simulador de nota e delta de re-escaneamento."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text

    # Abas para os 5 servidores exigidos
    for srv_id, srv_label in [
        ("nginx", "Nginx"),
        ("apache", "Apache"),
        ("caddy", "Caddy"),
        ("traefik", "Traefik"),
        ("kubernetes", "Ingress do Kubernetes"),
    ]:
        assert f"id: '{srv_id}'" in html
        assert srv_label in html

    # Botão de cópia de código e etapas progressivas do HSTS
    assert "copySnippet(finding, index)" in html
    assert "Copiar Código" in html
    assert "Copiado!" in html
    assert "finding.progressive_steps" in html

    # Simulação interativa de projeção de nota
    assert "getSimulatedScore()" in html
    assert "getSimulatedGrade()" in html
    assert "getProjectedSimulationText()" in html
    assert "Ao aplicar" in html
    assert "sua nota sobe para" in html

    # Botão Re-escanear Agora e Delta de Evolução
    assert "rescanTarget()" in html
    assert "Re-escanear Agora" in html
    assert "computeDelta(" in html
    assert "Delta de Evolução" in html


def test_dashboard_export_features_and_continuous_monitoring_sparklines():
    """Verifica exportação (Permalink, JSON, Markdown) e Sparklines SVG nos cards de monitoramento."""
    # Popula o cache de estado com histórico de latências para validar SSR e API /api/v1/targets
    sample_probe = ProbeResult(
        target_url="https://example.com",
        final_url="https://example.com/",
        resolved_ip="93.184.216.34",
        is_up=True,
        http_version="HTTP/2",
        status_code=200,
        timings=build_timing_breakdown(12.0, 18.0, 32.0, 45.0, 8.0),
        tls=TLSInspection(
            valid=True,
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            issuer="Let's Encrypt",
            subject="example.com",
            days_remaining=75,
            ocsp_stapling=True,
            ocsp_status="Ativo (Stapled)",
            cert_chain=["example.com", "R3", "ISRG Root X1"],
            sans=["example.com", "www.example.com"],
        ),
        security=SecurityAudit(grade="A", score=85),
    )
    _update_state_and_history(sample_probe)
    sample_probe.timings.total_ms = 98.5
    _update_state_and_history(sample_probe)

    # Verifica /api/v1/targets retornando history_ms para o Sparkline
    targets_resp = client.get("/api/v1/targets")
    assert targets_resp.status_code == 200
    targets_data = targets_resp.json()
    assert len(targets_data) == 1
    assert targets_data[0]["target_url"] == "https://example.com"
    assert targets_data[0]["history_ms"] == [115.0, 98.5]

    # Verifica renderização do dashboard com o alvo no cache SSR e funções de exportação/sparkline
    dash_resp = client.get("/")
    assert dash_resp.status_code == 200
    html = dash_resp.text

    assert "copyPermalink()" in html
    assert "exportJson()" in html
    assert "exportMarkdown()" in html
    assert "buildSparklinePoints(" in html
    assert "<svg" in html
    assert "<polyline" in html
    assert "https://example.com" in html
    assert 'data-history="115.0,98.5"' in html
    assert "ONLINE (200)" in html
    assert "Nota A" in html
