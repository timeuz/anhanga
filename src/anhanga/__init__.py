"""Anhangá — fonte única de versão: metadados do pacote (pyproject.toml)."""

from importlib import metadata as _metadata

try:
    __version__ = _metadata.version("anhanga")
except _metadata.PackageNotFoundError:  # execução direta do código-fonte, sem instalação
    __version__ = "0.0.0+local"
