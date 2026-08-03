"""Pytest bootstrap: makes `app` importable regardless of the invoking cwd
and adds the generated protobuf bindings to sys.path."""
import sys
from pathlib import Path

_PHISHGUARD = Path(__file__).resolve().parent
_PROTO = _PHISHGUARD.parent / "proto" / "gen" / "python"

for _p in (_PHISHGUARD, _PROTO):
    _s = str(_p)
    if _s not in sys.path:
        sys.path.insert(0, _s)
