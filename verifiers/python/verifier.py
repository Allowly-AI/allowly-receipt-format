"""Compatibility wrapper for the packaged Python verifier.

Prefer importing from ``allowly_receipt_format`` in application code.
This file remains so existing local commands keep working:

    python verifier.py path/to/receipt.json path/to/keys.json
"""

from __future__ import annotations

import sys
from pathlib import Path

_SRC = Path(__file__).with_name("src")
if _SRC.exists():
    sys.path.insert(0, str(_SRC))

from allowly_receipt_format.verifier import *  # noqa: F401,F403,E402
from allowly_receipt_format.verifier import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
