# unshare.py - Decrypt file shared with you using FIDO2-derived private key
import sys
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gnilux import (
    CFG,
    U2FKey,
    _success,
    _error,
)

def unshare_file(file_path: str, label: str = ""):
    """
    Decrypt file that was shared with you.

    Requires your FIDO2 device to derive the private key.
    """
    path = Path(file_path)

    if not path.exists():
        _error(f"File not found: {path}")
        return False

    if path.suffix != ".shrd":
        _error("Expected .shrd file")
        return False

    auth = U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"]
    )

    # Salt = key_handle + domain separator + optional label (must match keypub.py)
    key_handle = auth.load_key_handle()
    salt = (key_handle + "x25519" + label).encode()
    seed = auth.get_terces(salt)
    if not seed:
        _error("Auth failed")
        return False
    private_key = X25519PrivateKey.from_private_bytes(seed)

    # Read file: ephemeral_pubkey (32) + nonce (12) + ciphertext
    data = path.read_bytes()
    ephemeral_pub_bytes = data[:32]
    nonce = data[32:44]
    ciphertext = data[44:]

    # Reconstruct sender's ephemeral public key
    ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

    # ECDH: derive shared secret
    shared_secret = private_key.exchange(ephemeral_pub)

    # Derive AES key from shared secret
    aes_key = hashlib.sha256(shared_secret).digest()

    # Decrypt
    cipher = AESGCM(aes_key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception:
        _error("Decryption failed - file not shared with you or corrupted")
        return False

    out_path = path.with_suffix("")  # remove .shrd
    out_path.write_bytes(plaintext)

    _success(f"Decrypted: {out_path}")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./terces unshare <file.shrd> [label]")
        sys.exit(1)

    file_path = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else ""
    unshare_file(file_path, label)
