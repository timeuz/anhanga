from anhanga.engine.config import load_config, parse_config, parse_duration_ms


def test_valid_config_roundtrip():
    cfg = parse_config(
        {
            "interval_seconds": 30,
            "samples": 3,
            "slo": {"max_ttfb": "800ms", "max_total": "2s"},
            "min_grade": "c",
            "targets": [
                "https://a.example",
                {"url": "https://b.example", "samples": 5, "slo": {"max_ttfb": "300ms"}, "min_grade": "B"},
            ],
            "webhooks": [{"url": "https://hooks.slack.com/x", "provider": "slack"}],
            "alerting": {"failure_threshold": 3, "cooldown_seconds": 60, "notify_recovery": False},
        }
    )
    assert cfg.errors == [] and cfg.warnings == []
    a, b = cfg.targets
    assert (a.samples, a.rules.max_ttfb_ms, a.rules.max_total_ms, a.rules.min_grade) == (3, 800.0, 2000.0, "C")
    # alvo sobrescreve só o que informou; herda o resto
    assert (b.samples, b.rules.max_ttfb_ms, b.rules.max_total_ms, b.rules.min_grade) == (5, 300.0, 2000.0, "B")
    assert cfg.policy.failure_threshold == 3 and cfg.policy.notify_recovery is False
    assert cfg.policy.cooldown_seconds == 60.0


def test_interval_zero_is_clamped_not_busy_loop():
    cfg = parse_config({"interval_seconds": 0, "targets": ["https://a.example"]})
    assert cfg.interval_seconds == 5 and any("interval_seconds" in w for w in cfg.warnings)


def test_interval_wrong_type_reports_error():
    cfg = parse_config({"interval_seconds": "rápido", "targets": ["https://a.example"]})
    assert cfg.interval_seconds == 60 and any("interval_seconds" in e for e in cfg.errors)


def test_invalid_and_duplicate_targets_dropped():
    cfg = parse_config({"targets": ["https://ok.example", "file:///etc/passwd", "bad_host!.com", 42, "https://ok.example"]})
    assert [t.url for t in cfg.targets] == ["https://ok.example"]
    assert len(cfg.errors) == 3 and any("duplicado" in w for w in cfg.warnings)


def test_unset_env_var_webhook_is_rejected(monkeypatch, tmp_path):
    monkeypatch.delenv("HOOK_URL_UNSET", raising=False)
    f = tmp_path / "t.yaml"
    f.write_text('targets: ["https://a.example"]\nwebhooks:\n  - url: "${HOOK_URL_UNSET}"\n')
    cfg = load_config(f)
    assert cfg.webhooks == [] and any("vazia" in e for e in cfg.errors)


def test_telegram_requires_chat_id_and_accepts_documented_key():
    bad = parse_config({"webhooks": [{"url": "https://api.telegram.org/botX/sendMessage", "provider": "telegram"}]})
    assert bad.webhooks == [] and bad.errors
    ok = parse_config(
        {"webhooks": [{"url": "https://api.telegram.org/botX/sendMessage", "provider": "telegram", "telegram_chat_id": -100123}]}
    )
    assert ok.webhooks[0].chat_id == "-100123"


def test_bad_provider_and_scheme_rejected():
    cfg = parse_config({"webhooks": [{"url": "ftp://x"}, {"url": "https://x.example", "provider": "discord"}]})
    assert cfg.webhooks == [] and len(cfg.errors) == 2


def test_unknown_keys_warn_typos():
    cfg = parse_config({"intervall_seconds": 5, "alerting": {"cooldown": 1}})
    assert len(cfg.warnings) >= 2


def test_bad_slo_and_grade_reported():
    cfg = parse_config({"targets": [{"url": "https://a.example", "slo": {"max_ttfb": "abc"}, "min_grade": "Z"}]})
    assert len(cfg.errors) == 2 and cfg.targets[0].rules.max_ttfb_ms is None and cfg.targets[0].rules.min_grade is None


def test_broken_yaml_does_not_raise(tmp_path):
    f = tmp_path / "t.yaml"
    f.write_text("targets: [unclosed")
    cfg = load_config(f)
    assert cfg.errors and cfg.targets == []


def test_parse_duration():
    assert parse_duration_ms("500ms") == 500 and parse_duration_ms("1.5s") == 1500 and parse_duration_ms(250) == 250
    for bad in ("abc", "-1s", "0", ""):
        try:
            parse_duration_ms(bad)
        except ValueError:
            continue
        raise AssertionError(bad)
