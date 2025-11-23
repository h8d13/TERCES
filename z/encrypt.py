#encrypt.py
from gnilux import (
    CFG,
    U2FKey,
    uid,
    is_elevated,
    who_dat,
    _success,
    _error,
    _debug,
)

_debug(f"{uid} {is_elevated(uid)} {who_dat(uid)} ")

auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"], device_index=CFG["device_index"])

# --- ENCRYPT FLOW ---
if auth.authenticate():
    _success("Auth OK")
    name = input("Key Name: ").strip()
    secret = input("Secret: ").strip()
    description = input("Description (optional): ").strip()
    auth.encrypt_secret(name, secret, description)
else: 
    _error("Auth FAILED. Exiting...")
