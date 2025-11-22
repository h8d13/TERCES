#decrypt.py
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

# --- DECRYPT FLOW ---
if auth.authenticate():
    _success("Auth OK")
    name = input("Name: ").strip()
    token = auth.decrypt_secret(name)
    if token:
        print(f"\n{token}")
else:
    _error('Auth Failed.')
