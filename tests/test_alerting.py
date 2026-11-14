from anhanga.engine.alerting import AlertManager, detect_problems
from anhanga.engine.config import AlertPolicy, SLORules


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def mgr(**kw):
    clock = Clock()
    return AlertManager(AlertPolicy(**kw), clock=clock), clock


NO_RULES = SLORules()


def test_threshold_prevents_flapping_alert(mk):
    m, _ = mgr(failure_threshold=2)
    assert m.evaluate(mk(up=False, status=None, error="x"), NO_RULES) == []  # 1º ciclo: ainda não
    assert m.evaluate(mk(), NO_RULES) == []  # voltou: some em silêncio, sem alerta nem recuperação
    assert m.active_problems("https://t.example") == []


def test_alert_once_then_dedup(mk):
    m, clock = mgr(failure_threshold=2, cooldown_seconds=3600)
    down = lambda: mk(up=False, status=None, error="conexão recusada")  # noqa: E731
    assert m.evaluate(down(), NO_RULES) == []
    ev = m.evaluate(down(), NO_RULES)
    assert [e.kind for e in ev] == ["alert"] and "OFFLINE" in ev[0].messages[0]
    for _ in range(50):  # a cada ciclo, dentro do cooldown: silêncio
        clock.t += 30
        assert m.evaluate(down(), NO_RULES) == []


def test_reminder_after_cooldown(mk):
    m, clock = mgr(failure_threshold=1, cooldown_seconds=100)
    down = lambda: mk(up=False, status=None, error="x")  # noqa: E731
    assert m.evaluate(down(), NO_RULES)[0].kind == "alert"
    clock.t += 99
    assert m.evaluate(down(), NO_RULES) == []
    clock.t += 2
    ev = m.evaluate(down(), NO_RULES)
    assert [e.kind for e in ev] == ["reminder"]
    clock.t += 50
    assert m.evaluate(down(), NO_RULES) == []  # cooldown reinicia a cada lembrete


def test_cooldown_zero_means_no_reminders(mk):
    m, clock = mgr(failure_threshold=1, cooldown_seconds=0)
    m.evaluate(mk(up=False, status=None, error="x"), NO_RULES)
    clock.t += 10**6
    assert m.evaluate(mk(up=False, status=None, error="x"), NO_RULES) == []


def test_recovery_sent_once(mk):
    m, _ = mgr(failure_threshold=1, recovery_threshold=2)
    m.evaluate(mk(up=False, status=None, error="x"), NO_RULES)
    assert m.evaluate(mk(), NO_RULES) == []  # 1 ciclo saudável: ainda não declara
    ev = m.evaluate(mk(), NO_RULES)
    assert [e.kind for e in ev] == ["recovery"] and "resolvido" in ev[0].messages[0]
    assert m.evaluate(mk(), NO_RULES) == []


def test_recovery_can_be_disabled(mk):
    m, _ = mgr(failure_threshold=1, notify_recovery=False)
    m.evaluate(mk(up=False, status=None, error="x"), NO_RULES)
    assert m.evaluate(mk(), NO_RULES) == []


def test_recurrence_after_recovery_alerts_again(mk):
    m, _ = mgr(failure_threshold=1)
    down = lambda: mk(up=False, status=None, error="x")  # noqa: E731
    m.evaluate(down(), NO_RULES)
    m.evaluate(mk(), NO_RULES)
    assert m.evaluate(down(), NO_RULES)[0].kind == "alert"


def test_target_going_down_does_not_fake_recover_slo(mk):
    """Sem resposta não há medição: o SLO ativo não pode ser dado como 'resolvido'."""
    m, _ = mgr(failure_threshold=1)
    rules = SLORules(max_ttfb_ms=100)
    assert m.evaluate(mk(ttfb_ms=500, total_ms=600), rules)[0].kind == "alert"
    ev = m.evaluate(mk(up=False, status=None, error="x"), rules)
    assert [e.kind for e in ev] == ["alert"] and "OFFLINE" in ev[0].messages[0]  # só o down; sem 'recovery'
    assert set(m.active_problems("https://t.example")) == {"down", "slo_ttfb"}


def test_slo_uses_median_with_samples(mk):
    rules = SLORules(max_ttfb_ms=100)
    cold_inflated = mk(ttfb_ms=300, samples=3, ttfb_p50=60)  # TTFB frio h2 inflado; mediana ok
    assert "slo_ttfb" not in detect_problems(cold_inflated, rules)
    assert "slo_ttfb" in detect_problems(mk(ttfb_ms=300, samples=1), rules)


def test_total_and_grade_rules(mk):
    problems = detect_problems(mk(total_ms=3000, grade="D"), SLORules(max_total_ms=2000, min_grade="C"))
    assert set(problems) == {"slo_total", "grade"}
    assert detect_problems(mk(grade="B"), SLORules(min_grade="B")) == {}


def test_invalid_cert_and_expiring(mk):
    assert "degraded" in detect_problems(mk(tls_valid=False, tls_days=-5), NO_RULES)
    exp = detect_problems(mk(tls_days=7), NO_RULES)
    assert "tls_expiring" in exp and "degraded" not in exp


def test_multiple_problems_aggregate_in_one_event(mk):
    m, _ = mgr(failure_threshold=1)
    ev = m.evaluate(mk(tls_valid=False, grade="F", total_ms=9000), SLORules(max_total_ms=1000, min_grade="B"))
    assert len(ev) == 1 and len(ev[0].messages) == 3


def test_targets_are_independent_and_forget(mk):
    m, _ = mgr(failure_threshold=1)
    assert m.evaluate(mk("https://a.example", up=False, status=None, error="x"), NO_RULES)
    assert m.evaluate(mk("https://b.example"), NO_RULES) == []
    m.forget({"https://b.example"})
    assert m.active_problems("https://a.example") == []
