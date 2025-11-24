# file.py - FIDO2-backed file/folder encryption
import sys
import io
import tarfile
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
    """Encrypt a file or folder using FIDO2 hmac-secret derived key"""
    path = Path(file_path)

    if not path.exists():
        _error(f"Not found: {path}")
        return False

    if path.suffix == ".trcs":
        _error("Already encrypted (.trcs)")
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

    is_dir = path.is_dir()

    if is_dir:
        # Tar the folder
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            tar.add(path, arcname=path.name)
        plaintext = buf.getvalue()
        out_path = Path(f"{path}.tar.trcs")
        salt_name = path.name + ".tar"
    else:
        plaintext = path.read_bytes()
        out_path = Path(f"{path}.trcs")
        salt_name = path.name

    # Use key_handle + filename as salt
    key_handle = auth.load_key_handle()
    salt = (key_handle + salt_name).encode()
    key = auth.get_terces(salt)

    nonce = _random(12)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)

    out_path.write_bytes(nonce + ciphertext)

    _success(f"Encrypted: {out_path}")
    print(f"Original size: {len(plaintext)} bytes")
    if is_dir:
        print(f"You can now delete the folder: rm -r '{path}'")
    else:
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

    # Check if it's a tar archive (gzip magic bytes: 1f 8b)
    if plaintext[:2] == b'\x1f\x8b':
        buf = io.BytesIO(plaintext)
        with tarfile.open(fileobj=buf, mode='r:gz') as tar:
            tar.extractall(path=path.parent)
        # Get the folder name from tar
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode='r:gz') as tar:
            folder_name = tar.getnames()[0].split('/')[0]
        _success(f"Extracted: {path.parent / folder_name}")
    else:
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
