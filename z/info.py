#info.py
import sys
from gnilux import (
    CFG,
    info,
    is_venv,
    is_python,
    is_safe_path,
    username,
    _debug,
)

_debug(f"venv: {is_venv}")
_debug(f"python: {is_python}")
_debug(f"user: {username} (safe home path: {is_safe_path(username)})")

filter_pattern = sys.argv[1] if len(sys.argv) > 1 else None
info(filter_pattern=filter_pattern, device_index=CFG["device_index"])
