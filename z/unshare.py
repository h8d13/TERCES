# unshare.py - Decrypt file shared with you using FIDO2-derived private key
import sys
import struct
import hashlib
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gnilux import (
    CFG,
    U2FKey,
    _success,
    _error,
)

MAGIC = b"SHRD"


def unshare_file(file_path: str, label: str = ""):
    """
    Decrypt file that was shared with you 

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

    size = path.stat().st_size
    out_path = path.with_suffix("")  # remove .shrd
    t0 = time.time()

    try:
        with open(path, 'rb') as src, open(out_path, 'wb') as dst:
            # Read header: MAGIC + ephemeral_pubkey (32)
            if src.read(4) != MAGIC:
                _error("Invalid format (missing SHRD header)")
                return False

            ephemeral_pub_bytes = src.read(32)
            ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)

            # ECDH: derive shared secret
            shared_secret = private_key.exchange(ephemeral_pub)

            # Derive AES key from shared secret
            aes_key = hashlib.sha256(shared_secret).digest()

            # Stream decrypt
            cipher = AESGCM(aes_key)
            processed = 4 + 32  # magic + ephemeral pubkey already read

            while hdr := src.read(4):
                length = struct.unpack("<I", hdr)[0]
                nonce = src.read(12)
                enc = src.read(length)
                dec = cipher.decrypt(nonce, enc, None)
                dst.write(dec)
                processed += 4 + 12 + length
                pct = (processed / size) * 100
                print(f"\r[UNSHARE] {processed // (1024*1024)} MiB / {size // (1024*1024)} MiB ({pct:.0f}%)", end="", file=sys.stderr)

            print(file=sys.stderr)

    except Exception as e:
        out_path.unlink(missing_ok=True)
        _error(f"Decryption failed - file not shared with you or corrupted: {e}")
        return False

    elapsed = time.time() - t0
    mbs = (size / 1024 / 1024) / elapsed if elapsed > 0 else 0
    _success(f"Decrypted: {out_path} ({elapsed:.1f}s, {mbs:.0f} MiB/s)")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./terces unshare <file.shrd> [label]")
        sys.exit(1)

    file_path = sys.argv[1]
    label = sys.argv[2] if len(sys.argv) > 2 else ""
    unshare_file(file_path, label)
