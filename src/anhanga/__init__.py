"""Anhangá — fonte única de versão: metadados do pacote (pyproject.toml)."""

from importlib import metadata as _metadata

from anhanga.envfile import load_dotenv as _load_dotenv

# `.env` local ANTES de qualquer módulo do pacote: vários leem variáveis na importação
# (ex.: ANHANGA_SENSITIVE_COOKIE_REGEX em engine/security.py). Variáveis já definidas no ambiente têm precedência.
_load_dotenv()

try:
    __version__ = _metadata.version("anhanga")
except _metadata.PackageNotFoundError:  # execução direta do código-fonte, sem instalação
    __version__ = "0.0.0+local"
