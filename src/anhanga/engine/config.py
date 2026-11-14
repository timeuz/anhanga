"""Configuração validada do monitoramento contínuo (targets.yaml).

Nada aqui lança exceção por configuração ruim: erros viram mensagens em `MonitorConfig.errors`
(a entrada inválida é descartada) e ajustes automáticos viram `warnings`. O operador vê tudo no log.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

GRADE_RANK: dict[str, int] = {"A+": 6, "A": 5, "B": 4, "C": 3, "D": 2, "F": 1}

MIN_INTERVAL_SECONDS = 5
MAX_INTERVAL_SECONDS = 86_400
MAX_SAMPLES = 20
WEBHOOK_PROVIDERS = ("auto", "slack", "teams", "telegram")
_KNOWN_TOP_LEVEL = {
    "interval_seconds", "samples", "allow_private", "targets", "webhooks", "alerting", "slo", "min_grade", "storage",
}
_KNOWN_ALERTING = {"failure_threshold", "recovery_threshold", "cooldown_seconds", "notify_recovery"}


def parse_duration_ms(val: str | int | float) -> float:
    """Converte '500ms', '0.5s', '1m' ou '250' (ms) em milissegundos. ValueError se inválido ou <= 0."""
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
    return round(number * {"ms": 1.0, "s": 1000.0, "m": 60_000.0}[unit], 2)


@dataclass(frozen=True)
class SLORules:
    max_ttfb_ms: float | None = None
    max_total_ms: float | None = None
    min_grade: str | None = None


@dataclass(frozen=True)
class TargetSpec:
    url: str
    samples: int = 1
    allow_private: bool = False
    rules: SLORules = field(default_factory=SLORules)


@dataclass(frozen=True)
class WebhookSpec:
    url: str
    provider: str = "auto"
    chat_id: str | None = None
    allow_private: bool = False


@dataclass(frozen=True)
class AlertPolicy:
    failure_threshold: int = 2  # ciclos consecutivos com o problema antes de alertar (anti-flapping)
    recovery_threshold: int = 1  # ciclos consecutivos saudáveis antes de declarar recuperação
    cooldown_seconds: float = 3600.0  # intervalo entre lembretes enquanto persistir (0 = sem lembretes)
    notify_recovery: bool = True


@dataclass(frozen=True)
class StorageSpec:
    enabled: bool = True
    path: str = "anhanga.db"  # ANHANGA_DB_PATH sobrescreve; ":memory:" para efêmero
    retention_days: int = 14


@dataclass
class MonitorConfig:
    interval_seconds: int = 60
    allow_private: bool = False
    targets: list[TargetSpec] = field(default_factory=list)
    webhooks: list[WebhookSpec] = field(default_factory=list)
    policy: AlertPolicy = field(default_factory=AlertPolicy)
    storage: StorageSpec = field(default_factory=StorageSpec)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    load_failed: bool = False  # arquivo ilegível/YAML inválido/raiz não-mapa: não é uma config "vazia" legítima


_TRUE = {"true", "yes", "on", "1"}
_FALSE = {"false", "no", "off", "0"}


def _as_bool(value: Any, name: str, default: bool, cfg: MonitorConfig) -> bool:
    """Booleano estrito. `bool("false")` é True, e `${VAR}` interpolado chega sempre como string:
    aceita só bool real ou true/false/yes/no/on/off/1/0; qualquer outra coisa vira erro + `default`."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str) and value.strip().lower() in _TRUE | _FALSE:
        return value.strip().lower() in _TRUE
    cfg.errors.append(f"{name}: valor booleano inválido {value!r} (use true/false); usando {str(default).lower()}.")
    return default


def _interpolate_env_vars(obj: Any) -> Any:
    """Interpola ${VAR} recursivamente em strings, listas e dicionários."""
    if isinstance(obj, str):
        return re.sub(r"\$\{([A-Za-z0-9_]+)\}", lambda m: os.getenv(m.group(1), ""), obj)
    if isinstance(obj, list):
        return [_interpolate_env_vars(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _interpolate_env_vars(v) for k, v in obj.items()}
    return obj


def _as_int(value: Any, name: str, default: int, lo: int, hi: int, cfg: MonitorConfig) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        cfg.errors.append(f"{name}: valor inválido {value!r}; usando {default}.")
        return default
    ivalue = int(value)
    if ivalue < lo or ivalue > hi:
        clamped = max(lo, min(hi, ivalue))
        cfg.warnings.append(f"{name}: {ivalue} fora do intervalo [{lo}, {hi}]; usando {clamped}.")
        return clamped
    return ivalue


def _parse_rules(raw: Any, base: SLORules, where: str, cfg: MonitorConfig) -> SLORules:
    """Lê `slo:` (max_ttfb/max_total) e `min_grade`, herdando `base` para o que não foi informado."""
    if not isinstance(raw, dict):
        return base
    ttfb, total, grade = base.max_ttfb_ms, base.max_total_ms, base.min_grade
    slo = raw.get("slo")
    if slo is not None:
        if not isinstance(slo, dict):
            cfg.errors.append(f"{where}: 'slo' deve ser um mapa (max_ttfb / max_total).")
        else:
            for key in ("max_ttfb", "max_total"):
                if key in slo:
                    try:
                        value = parse_duration_ms(slo[key])
                    except ValueError as exc:
                        cfg.errors.append(f"{where}: slo.{key}: {exc}")
                        continue
                    if key == "max_ttfb":
                        ttfb = value
                    else:
                        total = value
    if raw.get("min_grade") is not None:
        candidate = str(raw["min_grade"]).strip().upper()
        if candidate in GRADE_RANK:
            grade = candidate
        else:
            cfg.errors.append(
                f"{where}: min_grade inválido '{raw['min_grade']}' (aceitos: {', '.join(GRADE_RANK)})."
            )
    return SLORules(max_ttfb_ms=ttfb, max_total_ms=total, min_grade=grade)


def _valid_target_url(raw_url: str) -> str | None:
    """Retorna a mensagem de erro, ou None se a URL do alvo for aceitável."""
    from anhanga.engine.probe import _normalize_and_validate_scheme, _validate_hostname_syntax

    normalized, err = _normalize_and_validate_scheme(raw_url)
    if err:
        return err
    parsed = urlparse(normalized)
    if not parsed.hostname:
        return "URL inválida: hostname não encontrado."
    try:
        _ = parsed.port
    except ValueError:
        return "URL inválida: porta fora do intervalo 1-65535."
    return _validate_hostname_syntax(parsed.hostname)


def parse_config(raw: Any) -> MonitorConfig:
    cfg = MonitorConfig()
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        cfg.errors.append("O arquivo de configuração deve ser um mapa YAML na raiz.")
        cfg.load_failed = True
        return cfg

    for key in raw:
        if key not in _KNOWN_TOP_LEVEL:
            cfg.warnings.append(f"Chave desconhecida ignorada: '{key}' (erro de digitação?).")

    if "interval_seconds" in raw:
        cfg.interval_seconds = _as_int(
            raw["interval_seconds"], "interval_seconds", 60, MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS, cfg
        )
    default_samples = (
        _as_int(raw["samples"], "samples", 1, 1, MAX_SAMPLES, cfg) if "samples" in raw else 1
    )
    cfg.allow_private = _as_bool(raw.get("allow_private", False), "allow_private", False, cfg)
    base_rules = _parse_rules(raw, SLORules(), "config", cfg)

    # alerting
    alerting = raw.get("alerting")
    if alerting is not None:
        if not isinstance(alerting, dict):
            cfg.errors.append("'alerting' deve ser um mapa.")
        else:
            for key in alerting:
                if key not in _KNOWN_ALERTING:
                    cfg.warnings.append(f"alerting: chave desconhecida ignorada: '{key}'.")
            cooldown = alerting.get("cooldown_seconds", cfg.policy.cooldown_seconds)
            if isinstance(cooldown, bool) or not isinstance(cooldown, (int, float)) or cooldown < 0:
                cfg.errors.append(f"alerting.cooldown_seconds: valor inválido {cooldown!r}; usando 3600.")
                cooldown = 3600.0
            cfg.policy = AlertPolicy(
                failure_threshold=_as_int(
                    alerting.get("failure_threshold", 2), "alerting.failure_threshold", 2, 1, 20, cfg
                ),
                recovery_threshold=_as_int(
                    alerting.get("recovery_threshold", 1), "alerting.recovery_threshold", 1, 1, 20, cfg
                ),
                cooldown_seconds=float(cooldown),
                notify_recovery=_as_bool(alerting.get("notify_recovery", True), "alerting.notify_recovery", True, cfg),
            )

    # storage
    storage = raw.get("storage")
    path = os.getenv("ANHANGA_DB_PATH") or "anhanga.db"
    enabled, retention = True, 14
    if storage is not None:
        if not isinstance(storage, dict):
            cfg.errors.append("'storage' deve ser um mapa (enabled, path, retention_days).")
        else:
            for key in storage:
                if key not in ("enabled", "path", "retention_days"):
                    cfg.warnings.append(f"storage: chave desconhecida ignorada: '{key}'.")
            enabled = _as_bool(storage.get("enabled", True), "storage.enabled", True, cfg)
            if isinstance(storage.get("path"), str) and storage["path"].strip() and not os.getenv("ANHANGA_DB_PATH"):
                path = storage["path"].strip()
            retention = _as_int(storage.get("retention_days", 14), "storage.retention_days", 14, 1, 3650, cfg)
    cfg.storage = StorageSpec(enabled=enabled, path=path, retention_days=retention)

    # targets
    raw_targets = raw.get("targets") or []
    if not isinstance(raw_targets, list):
        cfg.errors.append("'targets' deve ser uma lista.")
        raw_targets = []
    seen: set[str] = set()
    for idx, item in enumerate(raw_targets, start=1):
        where = f"targets[{idx}]"
        spec_raw: dict[str, Any]
        if isinstance(item, str):
            spec_raw = {"url": item}
        elif isinstance(item, dict) and isinstance(item.get("url"), str):
            spec_raw = item
        else:
            cfg.errors.append(f"{where}: esperado string ou mapa com 'url'; descartado.")
            continue
        url = spec_raw["url"].strip()
        err = _valid_target_url(url)
        if err:
            cfg.errors.append(f"{where} ('{url}'): {err} Descartado.")
            continue
        # Duplicata é decidida pela URL normalizada (é a chave de métricas, alertas e histórico).
        from anhanga.engine.probe import _normalize_and_validate_scheme

        norm = urlparse(_normalize_and_validate_scheme(url)[0])
        key = norm._replace(scheme=norm.scheme.lower(), netloc=norm.netloc.lower()).geturl()
        if key in seen:
            cfg.warnings.append(f"{where}: alvo duplicado '{url}' ignorado (mesmo alvo que '{key}').")
            continue
        seen.add(key)
        samples = (
            _as_int(spec_raw["samples"], f"{where}.samples", default_samples, 1, MAX_SAMPLES, cfg)
            if "samples" in spec_raw
            else default_samples
        )
        cfg.targets.append(
            TargetSpec(
                url=url,
                samples=samples,
                allow_private=_as_bool(spec_raw.get("allow_private", cfg.allow_private), f"{where}.allow_private", cfg.allow_private, cfg),
                rules=_parse_rules(spec_raw, base_rules, where, cfg),
            )
        )
    if not cfg.targets:
        cfg.warnings.append("Nenhum alvo válido configurado.")

    # webhooks
    raw_hooks = raw.get("webhooks") or []
    if not isinstance(raw_hooks, list):
        cfg.errors.append("'webhooks' deve ser uma lista.")
        raw_hooks = []
    for idx, item in enumerate(raw_hooks, start=1):
        where = f"webhooks[{idx}]"
        entry = {"url": item} if isinstance(item, str) else item
        if not isinstance(entry, dict) or not isinstance(entry.get("url"), str):
            cfg.errors.append(f"{where}: esperado string ou mapa com 'url'; descartado.")
            continue
        url = entry["url"].strip()
        if not url:
            cfg.errors.append(
                f"{where}: URL vazia (variável de ambiente ${{...}} não definida?); descartado."
            )
            continue
        if urlparse(url).scheme.lower() not in ("http", "https") or not urlparse(url).hostname:
            cfg.errors.append(f"{where}: URL de webhook inválida (http/https com host); descartado.")
            continue
        provider = str(entry.get("provider", "auto")).lower()
        if provider not in WEBHOOK_PROVIDERS:
            cfg.errors.append(
                f"{where}: provider inválido '{provider}' (aceitos: {', '.join(WEBHOOK_PROVIDERS)}); descartado."
            )
            continue
        chat_id = entry.get("chat_id", entry.get("telegram_chat_id"))
        chat_id = str(chat_id) if chat_id not in (None, "") else None
        if "api.telegram.org" in url or provider == "telegram":
            if not chat_id:
                cfg.errors.append(f"{where}: Telegram exige 'telegram_chat_id'; descartado.")
                continue
        cfg.webhooks.append(
            WebhookSpec(
                url=url,
                provider=provider,
                chat_id=chat_id,
                allow_private=_as_bool(entry.get("allow_private", cfg.allow_private), f"{where}.allow_private", cfg.allow_private, cfg),
            )
        )
    return cfg


def find_config_path(extra_candidates: list[Path] | None = None) -> Path | None:
    candidates = [Path(os.getenv("ANHANGA_CONFIG", "targets.yaml")), Path("targets.yaml")]
    candidates += list(extra_candidates or [])
    candidates.append(Path.cwd() / "targets.yaml")
    for path in candidates:
        if path.exists():
            return path
    return None


def load_config(path: Path | None) -> MonitorConfig:
    """Lê e valida o arquivo. Erros de leitura/YAML viram `errors` (config vazia), nunca exceção."""
    if path is None:
        return MonitorConfig()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        cfg = MonitorConfig()
        cfg.errors.append(f"Falha ao ler {path}: {exc}")
        cfg.load_failed = True
        return cfg
    return parse_config(_interpolate_env_vars(raw))
