"""Máquina de estados de alertas: anti-flapping, deduplicação, lembretes e recuperação.

Lógica pura (sem I/O): `AlertManager.evaluate()` recebe o ProbeResult de um ciclo e devolve os
eventos a notificar. Cada problema (down, degraded, slo_*, grade, tls_expiring) tem seu próprio estado
por alvo:

    saudável ──(N ciclos com o problema)──▶ ativo ──(cooldown)──▶ lembrete ──▶ ativo …
        ▲                                     │
        └────────(M ciclos saudáveis)─────────┘ ─▶ recuperação (1 notificação)

Notificações de um mesmo alvo e ciclo são agregadas num único evento.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Literal

from anhanga.engine.config import GRADE_RANK, AlertPolicy, SLORules
from anhanga.engine.models import ProbeResult

PROBLEM_LABELS: dict[str, str] = {
    "down": "Alvo offline",
    "degraded": "Certificado TLS inválido",
    "tls_expiring": "Certificado TLS expirando",
    "slo_ttfb": "SLO de TTFB",
    "slo_total": "SLO de latência total",
    "grade": "Nota de segurança abaixo do mínimo",
}


@dataclass
class AlertEvent:
    kind: Literal["alert", "reminder", "recovery"]
    target: str
    messages: list[str]


@dataclass
class _ProblemState:
    streak: int = 0
    clear_streak: int = 0
    active: bool = False
    last_notified: float = 0.0


@dataclass
class _TargetState:
    problems: dict[str, _ProblemState] = field(default_factory=dict)


def detect_problems(result: ProbeResult, rules: SLORules) -> dict[str, str]:
    """Problemas observáveis NESTE ciclo (chave -> mensagem). Só inclui chaves avaliáveis:
    sem resposta do alvo, apenas `down` é avaliado (SLO/TLS/nota não existem sem medição)."""
    problems: dict[str, str] = {}
    no_response = result.status_code is None
    if not result.is_up:
        problems["down"] = f"Alvo OFFLINE: {result.error or f'HTTP {result.status_code}'}"
    if no_response:
        return problems

    if result.health == "degraded":
        reason = (result.tls.validation_error if result.tls else None) or "validação falhou"
        problems["degraded"] = f"Certificado TLS inválido: {reason}"
    if (
        result.tls is not None
        and result.tls.valid
        and result.tls.alert_expiring
        and result.tls.days_remaining is not None
    ):
        problems["tls_expiring"] = f"Certificado TLS expira em {result.tls.days_remaining} dias"

    if rules.max_ttfb_ms is not None:
        ttfb_stats = result.sampling.phase_stats.get("ttfb") if result.sampling else None
        # Mediana das amostras quando existem (o TTFB frio em HTTP/2 é inflado), senão a medida única.
        ttfb = ttfb_stats.p50_ms if ttfb_stats and result.sampling.samples_count > 1 else result.timings.ttfb_ms
        if ttfb > rules.max_ttfb_ms:
            problems["slo_ttfb"] = f"TTFB {ttfb:.0f} ms excede o SLO de {rules.max_ttfb_ms:.0f} ms"
    if rules.max_total_ms is not None:
        total = (
            result.sampling.headline_total_ms
            if result.sampling and result.sampling.headline_total_ms > 0
            else result.timings.total_ms
        )
        if total > rules.max_total_ms:
            problems["slo_total"] = f"Latência total {total:.0f} ms excede o SLO de {rules.max_total_ms:.0f} ms"
    if rules.min_grade is not None:
        grade = result.security.grade
        if GRADE_RANK.get(grade, 1) < GRADE_RANK[rules.min_grade]:
            problems["grade"] = f"Nota {grade} abaixo do mínimo exigido ({rules.min_grade})"
    return problems


class AlertManager:
    def __init__(self, policy: AlertPolicy, clock: Callable[[], float] = time.monotonic) -> None:
        self.policy = policy
        self._clock = clock
        self._targets: dict[str, _TargetState] = {}

    def evaluate(self, result: ProbeResult, rules: SLORules) -> list[AlertEvent]:
        now = self._clock()
        state = self._targets.setdefault(result.target_url, _TargetState())
        problems = detect_problems(result, rules)
        no_response = result.status_code is None

        new_msgs: list[str] = []
        remind_msgs: list[str] = []
        recovered: list[str] = []

        for key, message in problems.items():
            st = state.problems.setdefault(key, _ProblemState())
            st.streak += 1
            st.clear_streak = 0
            if not st.active:
                if st.streak >= self.policy.failure_threshold:
                    st.active = True
                    st.last_notified = now
                    new_msgs.append(message)
            elif self.policy.cooldown_seconds > 0 and now - st.last_notified >= self.policy.cooldown_seconds:
                st.last_notified = now
                remind_msgs.append(message)

        for key in list(state.problems):
            if key in problems:
                continue
            # Sem resposta do alvo só `down` é avaliável: não declarar "recuperado" por falta de dado.
            if no_response and key != "down":
                continue
            st = state.problems[key]
            st.streak = 0
            if st.active:
                st.clear_streak += 1
                if st.clear_streak >= self.policy.recovery_threshold:
                    recovered.append(f"{PROBLEM_LABELS.get(key, key)}: resolvido")
                    del state.problems[key]
            else:
                del state.problems[key]  # problema que nunca chegou a alertar: some em silêncio

        events: list[AlertEvent] = []
        if new_msgs or remind_msgs:
            events.append(
                AlertEvent("alert" if new_msgs else "reminder", result.target_url, new_msgs + remind_msgs)
            )
        if recovered and self.policy.notify_recovery:
            events.append(AlertEvent("recovery", result.target_url, recovered))
        return events

    def active_problems(self, target: str) -> list[str]:
        st = self._targets.get(target)
        return sorted(k for k, p in st.problems.items() if p.active) if st else []

    def forget(self, keep_targets: set[str]) -> None:
        """Descarta o estado de alvos removidos da configuração."""
        for target in [t for t in self._targets if t not in keep_targets]:
            del self._targets[target]
