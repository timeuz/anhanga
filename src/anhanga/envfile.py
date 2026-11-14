"""Arquivo `.env` local: carga sem dependências e geração da chave da API.

Variáveis já definidas no ambiente têm precedência sobre o arquivo. O arquivo é criado com permissão 0600.
"""

import os
import secrets
from pathlib import Path

KEY_NAME = "ANHANGA_API_KEY"


def env_path() -> Path:
    return Path(os.environ.get("ANHANGA_ENV_FILE") or ".env")


def _parse(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name.strip():
            out[name.strip()] = value
    return out


def load_dotenv(path: Path | None = None) -> list[str]:
    """Carrega as variáveis do arquivo que ainda não existem no ambiente. Devolve os nomes aplicados."""
    target = path or env_path()
    try:
        values = _parse(target.read_text(encoding="utf-8"))
    except OSError:
        return []
    applied = []
    for name, value in values.items():
        if name not in os.environ:
            os.environ[name] = value
            applied.append(name)
    return applied


def generate_api_key(path: Path | None = None, force: bool = False) -> tuple[Path, str]:
    """Gera uma chave aleatória (256 bits) e a grava em `.env` (0600). Não sobrescreve sem `force`."""
    target = path or env_path()
    existing = ""
    try:
        existing = target.read_text(encoding="utf-8")
    except OSError:
        pass
    if KEY_NAME in _parse(existing) and not force:
        raise FileExistsError(f"{target} já define {KEY_NAME}; use --force para substituir")
    key = secrets.token_urlsafe(32)
    kept = [ln for ln in existing.splitlines() if _parse(ln).get(KEY_NAME) is None]
    body = "\n".join(kept + [f"{KEY_NAME}={key}"]) + "\n"
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(body)
    os.chmod(target, 0o600)
    return target, key
