# file.py - FIDO2-backed file/folder encryption (streaming, sequential)
import sys
import struct
import tempfile
import tarfile
import time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gnilux import (
    CFG,
    U2FKey,
    _random,
    _suuid,
    _success,
    _error,
)

CHUNK = 64 * 1024 * 1024  # 64MB chunks
MAGIC = b"TRCS"


def _enc_stream(src, dst, key, total_size: int = 0):
    """Encrypt file in streaming chunks"""
    dst.write(MAGIC)
    aesgcm = AESGCM(key)
    processed = 0

    while chunk := src.read(CHUNK):
        nonce = _random(12)
        enc = aesgcm.encrypt(nonce, chunk, None)
        dst.write(struct.pack("<I", len(enc)) + nonce + enc)
        processed += len(chunk)
        if total_size > 0:
            pct = (processed / total_size) * 100
            print(f"\r[ENC] {processed // (1024*1024)}MB / {total_size // (1024*1024)}MB ({pct:.0f}%)", end="", file=sys.stderr)

    if total_size > 0:
        print(file=sys.stderr)


def _dec_stream(src, dst, key, total_size: int = 0):
    """Decrypt file in streaming chunks"""
    if src.read(4) != MAGIC:
        return False

    aesgcm = AESGCM(key)
    processed = 4  # magic already read

    while hdr := src.read(4):
        length = struct.unpack("<I", hdr)[0]
        nonce = src.read(12)
        enc = src.read(length)
        dec = aesgcm.decrypt(nonce, enc, None)
        dst.write(dec)
        processed += 4 + 12 + length
        if total_size > 0:
            pct = (processed / total_size) * 100
            print(f"\r[DEC] {processed // (1024*1024)}MB / {total_size // (1024*1024)}MB ({pct:.0f}%)", end="", file=sys.stderr)

    if total_size > 0:
        print(file=sys.stderr)
    return True


def encrypt_file(file_path: str):
    path = Path(file_path)
    if not path.exists():
        _error(f"Not found: {path}")
    if path.suffix == ".trcs":
        _error("Already encrypted")

    auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"], device_index=CFG["device_index"])
    is_dir = path.is_dir()
    out_path = Path(f"{path}.tar.trcs" if is_dir else f"{path}.trcs")
    salt_name = path.name + (".tar" if is_dir else "")

    key = auth.get_terces((auth.load_key_handle() + salt_name).encode())

    t0 = time.time()
    if is_dir:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp:
            tmp_path = tmp.name
        with tarfile.open(tmp_path, 'w:gz') as tar:
            tar.add(path, arcname=path.name)
        size = Path(tmp_path).stat().st_size
        with open(tmp_path, 'rb') as src, open(out_path, 'wb') as dst:
            _enc_stream(src, dst, key, size)
        Path(tmp_path).unlink()
    else:
        size = path.stat().st_size
        with open(path, 'rb') as src, open(out_path, 'wb') as dst:
            _enc_stream(src, dst, key, size)

    elapsed = time.time() - t0
    mbs = (size / 1024 / 1024) / elapsed if elapsed > 0 else 0
    _success(f"Encrypted: {out_path} ({elapsed:.1f}s, {mbs:.0f} MB/s)")
    print(f"To delete original: rm {'-r ' if is_dir else ''}'{path}'", file=sys.stderr)
    return True


def decrypt_file(file_path: str):
    path = Path(file_path)
    if not path.exists():
        _error(f"Not found: {path}")
    if path.suffix != ".trcs":
        _error("Expected .trcs")

    auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"], device_index=CFG["device_index"])
    original_name = path.stem
    key = auth.get_terces((auth.load_key_handle() + original_name).encode())

    size = path.stat().st_size
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = tmp.name

    try:
        t0 = time.time()
        with open(path, 'rb') as src, open(tmp_path, 'wb') as dst:
            if not _dec_stream(src, dst, key, size):
                _error("Invalid format (missing TRCS header)")
        elapsed = time.time() - t0
        mbs = (size / 1024 / 1024) / elapsed if elapsed > 0 else 0

        # Check tar (gzip magic)
        with open(tmp_path, 'rb') as f:
            is_tar = f.read(2) == b'\x1f\x8b'

        if is_tar:
            with tarfile.open(tmp_path, 'r:gz') as tar:
                folder = tar.getnames()[0].split('/')[0]
                tar.extractall(path=path.parent)
            Path(tmp_path).unlink()
            _success(f"Extracted: {path.parent / folder} ({elapsed:.1f}s, {mbs:.0f} MB/s)")
        else:
            out_path = path.with_suffix("")
            if out_path.exists():
                out_path = out_path.with_stem(f"{out_path.stem}_{_suuid()}")
            Path(tmp_path).rename(out_path)
            _success(f"Decrypted: {out_path} ({elapsed:.1f}s, {mbs:.0f} MB/s)")
    except Exception as e:
        Path(tmp_path).unlink(missing_ok=True)
        _error(f"Decrypt failed: {e}")

    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./terces file <enc|dec> <path>", file=sys.stderr)
        sys.exit(1)
    cmd, file_path = sys.argv[1], sys.argv[2]
    if cmd in ("enc", "e"):
        encrypt_file(file_path)
    elif cmd in ("dec", "d"):
        decrypt_file(file_path)
    else:
        _error(f"Unknown: {cmd}")
