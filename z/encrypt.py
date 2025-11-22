#encrypt.py
# python-fido2 # python-cryptography
from gnilux import (
    U2FKey,
    uid,
    is_elevated,
    who_dat,
    _success,
    _error,
    _debug,
)

_debug(f"{uid} {is_elevated(uid)} {who_dat(uid)} ")

auth = U2FKey(mappings_file='/etc/u2f_mappings', use_pin=True)

# --- ENCRYPT FLOW ---
if auth.authenticate():
    _success("Auth OK")
    name = input("Key Name: ").strip()
    secret = input("Secret: ").strip()
    description = input("Description (optional): ").strip()
    auth.encrypt_secret(name, secret, description)
else: 
    _error("Auth FAILED. Exiting...")
