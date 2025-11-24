# share.py - Encrypt file for recipient using their public key
import sys
import base64
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gnilux import (
    _random,
    _success,
    _error,
)


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

    # Encrypt file
    plaintext = path.read_bytes()
    nonce = _random(12)
    cipher = AESGCM(aes_key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    # Output format: ephemeral_pubkey (32) + nonce (12) + ciphertext
    ephemeral_pub_bytes = ephemeral_public.public_bytes_raw()
    out_path = Path(f"{path}.shrd")
    out_path.write_bytes(ephemeral_pub_bytes + nonce + ciphertext)

    _success(f"Shared: {out_path}")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./terces share <file> <recipient_pubkey>")
        print("\nGet recipient's pubkey: ./terces keypub")
        sys.exit(1)

    file_path = sys.argv[1]
    pubkey = sys.argv[2]
    share_file(file_path, pubkey)
