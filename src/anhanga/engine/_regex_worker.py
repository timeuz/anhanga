"""Worker mínimo (importa apenas `re`) executado em subprocesso para isolar regex não confiável."""

import re


def run(conn, pattern: str, text: str) -> None:
    try:
        conn.send(("ok", bool(re.search(pattern, text))))
    except re.error as err:
        conn.send(("invalid", str(err)))
    except Exception as err:  # noqa: BLE001
        conn.send(("invalid", f"{type(err).__name__}: {err}"))
    finally:
        conn.close()
