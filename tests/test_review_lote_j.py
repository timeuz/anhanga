"""Lote J: P95/P99 só existem com amostras suficientes (n>=20 / n>=100) em /metrics, nos alertas e no export Markdown."""
import json
import re
from pathlib import Path

import pytest

import anhanga.main as app_main
from anhanga.engine import webhooks as W
from anhanga.metrics import exporter as E

HTML = (Path(app_main.BASE_DIR) / "web" / "templates" / "index.html").read_text(encoding="utf-8")


def _res(mk, url, n, p95_valid, p99_valid):
    r = mk(url, samples=n)
    r.sampling.p95_ms, r.sampling.p99_ms = 321.0, 987.0
    r.sampling.p95_valid, r.sampling.p99_valid = p95_valid, p99_valid
    return r


def _scrape():
    return E.render_prometheus_metrics()[0].decode()


def _quantiles(url):
    out = {}
    for ln in _scrape().splitlines():
        if ln.startswith("anhanga_probe_latency_quantile_seconds{") and f'target="{url}"' in ln:
            q = re.search(r'quantile="([^"]+)"', ln).group(1)
            out[q] = float(ln.rsplit(" ", 1)[1])
    return out


@pytest.fixture
def url():
    u = "https://j.example"
    yield u
    E.forget_target(u)


def test_few_samples_export_only_the_median(mk, url):
    E.record_probe_metrics(_res(mk, url, 3, False, False))
    assert set(_quantiles(url)) == {"0.5"}


def test_p95_appears_at_20_samples_and_p99_only_at_100(mk, url):
    E.record_probe_metrics(_res(mk, url, 20, True, False))
    assert _quantiles(url)["0.95"] == 0.321 and "0.99" not in _quantiles(url)
    E.record_probe_metrics(_res(mk, url, 100, True, True))
    assert _quantiles(url)["0.99"] == 0.987


def test_series_are_removed_when_a_later_cycle_has_too_few_samples(mk, url):
    E.record_probe_metrics(_res(mk, url, 100, True, True))
    assert {"0.95", "0.99"} <= set(_quantiles(url))
    E.record_probe_metrics(_res(mk, url, 3, False, False))
    assert set(_quantiles(url)) == {"0.5"}  # sem valor obsoleto do ciclo anterior


def test_no_fake_quantile_in_the_scrape_output_for_a_single_sample(mk, url):
    E.record_probe_metrics(mk(url))
    assert set(_quantiles(url)) == {"0.5"}


def _slack_fields(payload):
    return json.dumps(payload, ensure_ascii=False)


def test_slack_alert_shows_p95_only_when_valid(mk):
    few = _slack_fields(W.build_slack_payload(_res(mk, "https://a.example", 3, False, False), ["x"]))
    assert "P95" not in few
    ok = _slack_fields(W.build_slack_payload(_res(mk, "https://a.example", 20, True, False), ["x"]))
    assert "P95: 321" in ok


def test_slack_alert_never_labels_the_total_latency_as_p95(mk):
    r = mk("https://a.example")
    r.sampling = None  # sem amostragem: antes a latência total saía como "P95"
    assert "P95" not in _slack_fields(W.build_slack_payload(r, ["x"]))


def test_markdown_export_does_not_print_unsampled_percentiles():
    assert "r.sampling?.p95_valid ? r.sampling.p95_ms" in HTML and "r.sampling?.p99_valid ? r.sampling.p99_ms" in HTML
    assert "P95: \\`${r.sampling?.p95_ms || 0} ms\\`" not in HTML
