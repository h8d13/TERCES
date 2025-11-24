#decrypt.py
from gnilux import (
    CFG,
    U2FKey,
    uid,
    is_elevated,
    who_dat,
    _debug,
    _error,
)

_debug(f"{uid} {is_elevated(uid)} {who_dat(uid)} ")

auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"], device_index=CFG["device_index"])

# --- DECRYPT FLOW ---
name = input("Name: ").strip()
token = auth.decrypt_secret(name)
if token:
    print(f"\n{token}")
else:
    _error("Not found or auth failed")
