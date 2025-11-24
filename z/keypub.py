# keypub.py - Export FIDO2-derived public key for asymmetric sharing
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from gnilux import (
    CFG,
    U2FKey,
    _success,
    _error,
)

def export_pubkey():
    """Derive X25519 keypair from FIDO2 and export public key"""
    auth = U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"]
    )

    if not auth.authenticate():
        _error("Auth failed")
        return None

    _success("Auth OK")

    # Salt = key_handle + domain separator (unique per credential)
    key_handle = auth.load_key_handle()
    salt = (key_handle + "x25519").encode()
    seed = auth.get_terces(salt)

    # Generate X25519 keypair from seed
    private_key = X25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()

    # Export as base64
    pub_bytes = public_key.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode()

    print(pub_b64)
    return pub_b64


if __name__ == "__main__":
    export_pubkey()
