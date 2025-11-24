# gen.py - Generate and optionally store a secure password
import sys
import string
import secrets

from gnilux import (
    CFG,
    U2FKey,
    _success,
    _error,
)

CHARSET = string.ascii_letters + string.digits + "!@#$%^&*"


def generate(length: int = 24, store_as: str | None = None):
    """Generate a secure password, optionally store it"""
    password = ''.join(secrets.choice(CHARSET) for _ in range(length))

    print(password)

    if store_as:
        auth = U2FKey(
            mappings_file=CFG["mappings_file"],
            rp_id=CFG["rp_id"],
            device_index=CFG["device_index"]
        )

        if not auth.authenticate():
            _error("Auth failed - password not stored")
            return password

        # Count existing gen entries for index
        index = auth._load_index()
        gen_count = sum(1 for v in index.values() if v.get("description", "").startswith("gen"))
        auth.encrypt_secret(store_as, password, f"gen{gen_count}")
        _success(f"Stored as: {store_as}")

    return password


if __name__ == "__main__":
    length = 24
    store_as = None

    for arg in sys.argv[1:]:
        if arg.isdigit():
            length = int(arg)
        else:
            store_as = arg

    generate(length, store_as)
