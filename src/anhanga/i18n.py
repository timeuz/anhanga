"""idioma dos textos que o backend devolve (achados, erros, avisos).

o padrão é pt-BR, então o monitor, o CLI e os alertas continuam como sempre.
só a API de scan troca para en-US quando recebe `lang=en-US`.
"""

import os
from contextvars import ContextVar

SUPPORTED = ("pt-BR", "en-US")


def _is_english(value: str | None) -> bool:
    return bool(value) and value.strip().lower().startswith("en")


def default_lang() -> str:
    """idioma padrão do processo: `ANHANGA_LANG` (CLI, monitor e alertas), pt-BR se não houver."""
    return "en-US" if _is_english(os.getenv("ANHANGA_LANG")) else "pt-BR"


_lang: ContextVar[str | None] = ContextVar("anhanga_lang", default=None)


def normalize(value: str | None) -> str:
    """aceita 'en', 'en-us', 'EN-US'... ; sem valor usa o padrão do processo; o resto cai em pt-BR."""
    if not value or not value.strip():
        return default_lang()
    return "en-US" if _is_english(value) else "pt-BR"


def set_lang(value: str | None):
    """define o idioma do contexto atual; devolve o token para `reset_lang`."""
    return _lang.set(normalize(value))


def reset_lang(token) -> None:
    _lang.reset(token)


def get_lang() -> str:
    return _lang.get() or default_lang()


def tr(pt: str, en: str) -> str:
    """devolve o texto no idioma do contexto atual."""
    return en if get_lang() == "en-US" else pt


class LStr(str):
    """texto fixo em pt-BR que carrega a versão em inglês junto (continua sendo um `str` normal)."""

    en: str

    def __new__(cls, pt: str, en: str):
        obj = super().__new__(cls, pt)
        obj.en = en
        return obj


def tx(text):
    """versão do texto no idioma atual; texto comum (sem versão em inglês) volta como está."""
    if get_lang() == "en-US" and isinstance(text, LStr):
        return text.en
    return text
