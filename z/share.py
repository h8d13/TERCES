# share.py - Encrypt file for recipient using their public key
import sys
import struct
import base64
import hashlib
import time
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gnilux import (
    _random,
    _success,
    _error,
)

CHUNK = 64 * 1024 * 1024  # 64 MiB chunks
MAGIC = b"SHRD"


def share_file(file_path: str, recipient_pubkey: str):
    """
    Encrypt file for recipient using X25519 + AESGCM hybrid encryption.
    Anyone can encrypt for a recipient - no FIDO2 needed for sender.
    Only the recipient (with their FIDO2 device) can decrypt.
    """
    path = Path(file_path)

    if not path.exists():
        _error(f"File not found: {path}")
        return False

    if path.suffix == ".shrd":
        _error("File already shared (.shrd)")
        return False

    # Decode recipient's public key
    try:
        recipient_pub_bytes = base64.b64decode(recipient_pubkey)
        recipient_pub = X25519PublicKey.from_public_bytes(recipient_pub_bytes)
    except Exception:
        _error("Invalid public key format (expected base64)")
        return False

    # Generate ephemeral keypair for this encryption
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()

    # ECDH: derive shared secret
    shared_secret = ephemeral_private.exchange(recipient_pub)

    # Derive AES key from shared secret
    aes_key = hashlib.sha256(shared_secret).digest()

    # Stream encrypt
    size = path.stat().st_size
    out_path = Path(f"{path}.shrd")
    t0 = time.time()

    with open(path, 'rb') as src, open(out_path, 'wb') as dst:
        # Header: MAGIC + ephemeral_pubkey (32)
        dst.write(MAGIC)
        dst.write(ephemeral_public.public_bytes_raw())

        cipher = AESGCM(aes_key)
        processed = 0

        while chunk := src.read(CHUNK):
            nonce = _random(12)
            enc = cipher.encrypt(nonce, chunk, None)
            dst.write(struct.pack("<I", len(enc)) + nonce + enc)
            processed += len(chunk)
            pct = (processed / size) * 100
            print(f"\r[SHARE] {processed // (1024*1024)} MiB / {size // (1024*1024)} MiB ({pct:.0f}%)", end="", file=sys.stderr)

        print(file=sys.stderr)

    elapsed = time.time() - t0
    mbs = (size / 1024 / 1024) / elapsed if elapsed > 0 else 0
    _success(f"Shared: {out_path} ({elapsed:.1f}s, {mbs:.0f} MiB/s)")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./terces share <file> <recipient_pubkey>")
        print("\nGet recipient's pubkey: ./terces keypub")
        sys.exit(1)

    file_path = sys.argv[1]
    pubkey = sys.argv[2]
    share_file(file_path, pubkey)
