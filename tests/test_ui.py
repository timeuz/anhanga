"""Contratos estáticos do dashboard (sem navegador): i18n completo e endpoints coerentes com a API."""

import re
from pathlib import Path

import anhanga.main as app_main

HTML = (Path(app_main.BASE_DIR) / "web" / "templates" / "index.html").read_text(encoding="utf-8")


def _dict_keys(lang: str, next_lang: str | None) -> set[str]:
    start = HTML.index(f"'{lang}': {{")
    end = HTML.index(f"'{next_lang}': {{") if next_lang else HTML.index("function anhangaApp")
    return set(re.findall(r"^\s{16}(\w+):", HTML[start:end], re.M))


def test_every_translation_key_exists_in_both_languages():
    pt, en = _dict_keys("pt-BR", "en-US"), _dict_keys("en-US", None)
    assert pt == en, f"só em PT: {sorted(pt - en)} | só em EN: {sorted(en - pt)}"
    used = set(re.findall(r"\bt\('(\w+)'\)", HTML)) | {f"problem_{k}" for k in (
        "down", "degraded", "tls_expiring", "slo_ttfb", "slo_total", "grade")}
    used |= {f"cspStrength_{k}" for k in ("strong", "moderate", "weak", "report_only")}
    used |= {"revGood", "revRevoked", "revUnknown", "revUnavailable", "revError"}
    used |= {f[1] for f in re.findall(r"\['(\w+)','(filter\w+)'", HTML)}
    missing = sorted(k for k in used if k not in pt)
    assert not missing, f"chaves usadas e não traduzidas: {missing}"


def test_dashboard_uses_only_existing_api_routes():
    routes = {r.path for r in app_main.app.routes}
    for path in re.findall(r"apiFetch\('(/[^'?]+)", HTML):
        assert path in routes, path


def test_problem_keys_cover_every_alert_problem():
    from anhanga.engine.alerting import PROBLEM_LABELS

    for key in PROBLEM_LABELS:
        assert f"problem_{key}:" in HTML, key


def test_polling_does_not_reprompt_for_api_key_every_cycle():
    assert "keyPromptShown" in HTML


def test_filter_chips_have_room_for_their_focus_ring_inside_the_paint_contained_section():
    # a seção .defer usa content-visibility:auto e clipa o que sai da caixa; o contorno do filtro ativo sai 2px
    css = (Path(app_main.BASE_DIR) / "web" / "static" / "app.css").read_text(encoding="utf-8")
    assert 'class="filter-row ' in HTML
    m = re.search(r"\.filter-row\s*\{\s*padding:\s*(\d+)px", css)
    assert m and int(m.group(1)) >= 2, "sem folga >= 2px para o contorno dos filtros"


def test_ui_shows_the_untested_legacy_ciphers_note_in_both_languages():
    assert "result.tls.enumeration.legacy_ciphers_untested" in HTML
    assert HTML.count("tlsLegacyUntested:") == 2


def test_permalink_button_label_is_copy_analysis_link():
    assert "permalinkBtn: 'Copiar Link da Análise'" in HTML
    assert "permalinkBtn: 'Copy Analysis Link'" in HTML
    assert "Link Permanente" not in HTML.replace("<!-- Barra de Ferramentas: Re-escanear & Exportação (Link Permanente, JSON, Markdown) -->", "")
