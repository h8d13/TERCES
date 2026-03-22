#encrypt.py - Stores a secret in vault and let's you use stdin
import sys
from gnilux import (
    CFG,
    U2FKey,
    uid,
    is_elevated,
    who_dat,
    _debug,
    _success,
    _error,
)

_debug(f"{uid} {is_elevated(uid)} {who_dat(uid)} ")

auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"], device_index=CFG["device_index"])

# --- ENCRYPT FLOW ---
# Pipe: cat secret | ./terces encrypt <name> [desc]
# Interactive: ./terces encrypt
if not sys.stdin.isatty():
    if len(sys.argv) < 2:
        _error("Usage: <stdin> | ./terces encrypt <name> [description]")
        sys.exit(1)
    name = sys.argv[1]
    description = sys.argv[2] if len(sys.argv) > 2 else ""
    secret = sys.stdin.read().strip()
else:
    name = input("Key Name: ").strip()
    secret = input("Secret: ").strip()
    description = input("Description (optional): ").strip()

if auth.encrypt_secret(name, secret, description):
    _success("Stored")
