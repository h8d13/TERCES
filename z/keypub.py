# keypub.py - Export FIDO2-derived public key for asymmetric sharing
import sys
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from gnilux import (
    CFG,
    U2FKey,
    _success,
)

def export_pubkey(label: str = ""):
    """Derive X25519 keypair from FIDO2 and export public key"""
    auth = U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"]
    )

    # Salt = key_handle + domain separator + optional label
    key_handle = auth.load_key_handle()
    salt = (key_handle + "x25519" + label).encode()
    seed = auth.get_terces(salt)

    # Generate X25519 keypair from seed
    private_key = X25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()

    # Export as base64
    pub_bytes = public_key.public_bytes_raw()
    pub_b64 = base64.b64encode(pub_bytes).decode()

    _success("Public key:")
    print(pub_b64)
    return pub_b64


if __name__ == "__main__":
    label = sys.argv[1] if len(sys.argv) > 1 else ""
    export_pubkey(label)
