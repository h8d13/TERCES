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

_debug(f'{auth.check_perms()}')

if auth.authenticate():
    _success("Auth OK")
else:
    _error("Auth failed. Exiting...")