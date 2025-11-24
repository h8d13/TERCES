#encrypt.py
from gnilux import (
    CFG,
    U2FKey,
    uid,
    is_elevated,
    who_dat,
    _debug,
    _success,
)

_debug(f"{uid} {is_elevated(uid)} {who_dat(uid)} ")

auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"], device_index=CFG["device_index"])

# --- ENCRYPT FLOW ---
name = input("Key Name: ").strip()
secret = input("Secret: ").strip()
description = input("Description (optional): ").strip()
if auth.encrypt_secret(name, secret, description):
    _success("Stored")
