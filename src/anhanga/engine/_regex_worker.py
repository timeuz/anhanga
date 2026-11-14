"""Worker mínimo (só `re`/`json`) executado em subprocesso isolado para avaliar regex não confiável.

Protocolo: stdin = JSON {"pattern", "text"}; stdout = JSON ["ok", bool] | ["invalid", msg].
"""

import json
import re
import sys


def main() -> None:
    data = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    try:
        out = ["ok", bool(re.search(data["pattern"], data["text"]))]
    except re.error as err:
        out = ["invalid", str(err)]
    except Exception as err:  # noqa: BLE001
        out = ["invalid", f"{type(err).__name__}: {err}"]
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
