# file.py - FIDO2-backed file encryption
import sys
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gnilux import (
    CFG,
    U2FKey,
    _random,
    _success,
    _error,
)


def encrypt_file(file_path: str):
    """Encrypt a file using FIDO2 hmac-secret derived key"""
    path = Path(file_path)

    if not path.exists():
        _error(f"File not found: {path}")
        return False

    if path.suffix == ".trcs":
        _error("File already encrypted (.trcs)")
        return False

    auth = U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"]
    )

    if not auth.authenticate():
        _error("Auth failed")
        return False

    _success("Auth OK")

    # Use key_handle + filename as salt (same security model as secrets)
    key_handle = auth.load_key_handle()
    salt = (key_handle + path.name).encode()
    key = auth.get_terces(salt)

    plaintext = path.read_bytes()
    nonce = _random(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    out_path = Path(f"{path}.trcs")
    out_path.write_bytes(nonce + ciphertext)

    _success(f"Encrypted: {out_path}")
    print(f"Original size: {len(plaintext)} bytes")
    print(f"You can now delete the original: rm '{path}'")
    return True


def decrypt_file(file_path: str):
    """Decrypt a .trcs file using FIDO2 hmac-secret derived key"""
    path = Path(file_path)

    if not path.exists():
        _error(f"File not found: {path}")
        return False

    if path.suffix != ".trcs":
        _error("Expected .trcs file")
        return False

    auth = U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"]
    )

    if not auth.authenticate():
        _error("Auth failed")
        return False

    _success("Auth OK")

    # Derive same key using key_handle + original filename
    key_handle = auth.load_key_handle()
    original_name = path.stem  # removes .trcs
    salt = (key_handle + original_name).encode()
    key = auth.get_terces(salt)

    data = path.read_bytes()
    nonce, ciphertext = data[:12], data[12:]

    cipher = AESGCM(key)
    try:
        plaintext = cipher.decrypt(nonce, ciphertext, None)
    except Exception:
        _error("Decryption failed - wrong key or corrupted file")
        return False

    out_path = path.with_suffix("")  # remove .trcs
    out_path.write_bytes(plaintext)

    _success(f"Decrypted: {out_path}")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./terces file <enc|dec> <path>")
        sys.exit(1)

    cmd = sys.argv[1]
    file_path = sys.argv[2]

    if cmd in ("enc", "e"):
        encrypt_file(file_path)
    elif cmd in ("dec", "d"):
        decrypt_file(file_path)
    else:
        _error(f"Unknown command: {cmd}")
        print("Usage: ./terces file <enc|dec> <path>")
        sys.exit(1)
