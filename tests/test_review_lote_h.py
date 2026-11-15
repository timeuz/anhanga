"""Lote H: P95/P99 alcançáveis na UI e aviso honesto sobre o P99 em scan avulso."""
from pathlib import Path

import anhanga.main as app_main
from anhanga.engine.models import SampleMeasurement, TimingBreakdown
from anhanga.engine.probe import _build_sampling_stats

HTML = (Path(app_main.BASE_DIR) / "web" / "templates" / "index.html").read_text(encoding="utf-8")


def _samples(n):
    return [SampleMeasurement(sample_index=i, timings=TimingBreakdown(total_ms=100.0 + i)) for i in range(n)]


def test_ui_offers_20_samples_and_accepts_it_from_the_url():
    assert '<option value="20"' in HTML
    assert "[1, 3, 5, 10, 20].includes(samplesParam)" in HTML


def test_api_accepts_exactly_the_ui_maximum():
    q = [r for r in app_main.app.routes if getattr(r, "path", "") == "/api/v1/scan"][0]
    param = next(p for p in q.dependant.query_params if p.name == "samples")
    assert any(getattr(m, "le", None) == 20 for m in param.field_info.metadata)


def test_20_samples_make_p95_valid_but_p99_stays_with_an_explanatory_notice():
    st = _build_sampling_stats(_samples(20))
    assert st.p95_valid and not st.p99_valid
    assert st.sample_size_notice and "P99" in st.sample_size_notice and "histogram_quantile" in st.sample_size_notice


def test_10_samples_keep_both_invalid_with_the_generic_notice():
    st = _build_sampling_stats(_samples(10))
    assert not st.p95_valid and not st.p99_valid
    assert "n < 20" in st.sample_size_notice


def test_100_samples_need_no_notice():
    st = _build_sampling_stats(_samples(100))
    assert st.p99_valid and st.sample_size_notice is None


def test_p99_card_label_stays_short_so_it_fits_the_card_and_the_tooltip_carries_the_explanation():
    # "N/D (histórico)" estourava o cartão (whitespace-nowrap) em ~5 px; o rótulo curto cabe e o title explica.
    assert "'N/D (n<100)'" in HTML and "N/D (histórico)" not in HTML
    assert HTML.count(':title="result?.sampling?.sample_size_notice || \'\'"') >= 2
