# file.py - FIDO2-backed file/folder encryption (streaming, sequential)
import sys
import struct
import subprocess
import shutil
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
    _debug,
)

CHUNK = 64 * 1024 * 1024  # 64 MiB chunks
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
            print(f"\r[ENC] {processed // (1024*1024)} MiB / {total_size // (1024*1024)} MiB ({pct:.0f}%)", end="", file=sys.stderr)

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
            print(f"\r[DEC] {processed // (1024*1024)} MiB / {total_size // (1024*1024)} MiB ({pct:.0f}%)", end="", file=sys.stderr)

    if total_size > 0:
        print(file=sys.stderr)
    return True


def encrypt_file(file_path: str, dest: str | None = None):
    path = Path(file_path)
    if not path.exists():
        _error(f"Not found: {path}")
    if path.suffix == ".trcs":
        _error("Already encrypted")

    auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"], device_index=CFG["device_index"])
    is_dir = path.is_dir()
    default_name = f"{path.name}.tar.trcs" if is_dir else f"{path.name}.trcs"

    if dest:
        dest_path = Path(dest)
        if dest_path.is_dir():
            out_path = dest_path / default_name
        else:
            out_path = dest_path
    else:
        out_path = path.parent / default_name

    salt_name = path.name + (".tar" if is_dir else "")

    key = auth.get_terces((auth.load_key_handle() + salt_name).encode())

    if is_dir:
        # Count files for progress
        all_files = list(path.rglob('*'))
        file_count = len([f for f in all_files if f.is_file()])
        added = [0]

        def tar_filter(tarinfo):
            if tarinfo.isfile():
                added[0] += 1
                print(f"\r[TAR] {added[0]}/{file_count} files", end="", file=sys.stderr)
            return tarinfo

        compression = CFG.get("compression", "zstd")
        has_zstd = shutil.which("zstd") is not None
        has_lz4 = shutil.which("lz4") is not None

        t_tar = time.time()
        if compression == "lz4" and has_lz4:
            # Create uncompressed tar, then pipe through lz4
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar') as tmp:
                tar_path = tmp.name
            with tarfile.open(tar_path, 'w') as tar:
                tar.add(path, arcname=path.name, filter=tar_filter)
            print(" compressing...", end="", file=sys.stderr)
            tmp_path = tar_path + ".lz4"
            subprocess.run(["lz4", "-q", "--rm", tar_path, tmp_path], check=True)
        elif compression == "zstd" and has_zstd:
            # Create uncompressed tar, then pipe through zstd
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar') as tmp:
                tar_path = tmp.name
            with tarfile.open(tar_path, 'w') as tar:
                tar.add(path, arcname=path.name, filter=tar_filter)
            print(" compressing...", end="", file=sys.stderr)
            tmp_path = tar_path + ".zst"
            subprocess.run(["zstd", "-q", "--rm", "-o", tmp_path, tar_path], check=True)
        elif compression == "none":
            # No compression
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar') as tmp:
                tmp_path = tmp.name
            with tarfile.open(tmp_path, 'w') as tar:
                tar.add(path, arcname=path.name, filter=tar_filter)
        else:
            # Fallback to gzip
            if compression == "lz4" and not has_lz4:
                _debug("lz4 not found, using gzip")
            if compression == "zstd" and not has_zstd:
                _debug("zstd not found, using gzip")
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp:
                tmp_path = tmp.name
            with tarfile.open(tmp_path, 'w:gz') as tar:
                tar.add(path, arcname=path.name, filter=tar_filter)

        tar_elapsed = time.time() - t_tar
        comp_label = compression if (compression == "lz4" and has_lz4) or (compression == "zstd" and has_zstd) else ("none" if compression == "none" else "gzip")
        print(f" [{comp_label}] ({tar_elapsed:.1f}s)", file=sys.stderr)

        size = Path(tmp_path).stat().st_size
        t_enc = time.time()
        with open(tmp_path, 'rb') as src, open(out_path, 'wb') as dst:
            _enc_stream(src, dst, key, size)
        enc_elapsed = time.time() - t_enc
        Path(tmp_path).unlink()

        mbs = (size / 1024 / 1024) / enc_elapsed if enc_elapsed > 0 else 0
        _success(f"Encrypted: {out_path} (tar:{tar_elapsed:.1f}s enc:{enc_elapsed:.1f}s, {mbs:.0f} MiB/s)")
    else:
        size = path.stat().st_size
        t0 = time.time()
        with open(path, 'rb') as src, open(out_path, 'wb') as dst:
            _enc_stream(src, dst, key, size)
        elapsed = time.time() - t0
        mbs = (size / 1024 / 1024) / elapsed if elapsed > 0 else 0
        _success(f"Encrypted: {out_path} ({elapsed:.1f}s, {mbs:.0f} MiB/s)")
    print(f"To delete original: rm {'-r ' if is_dir else ''}'{path}'", file=sys.stderr)
    return True


def decrypt_file(file_path: str, dest: str | None = None):
    path = Path(file_path)
    if not path.exists():
        _error(f"Not found: {path}")
    if path.suffix != ".trcs":
        _error("Expected .trcs")

    auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"], device_index=CFG["device_index"])
    original_name = path.stem
    key = auth.get_terces((auth.load_key_handle() + original_name).encode())

    # Determine output location
    if dest:
        dest_path = Path(dest)
        if dest_path.is_dir():
            extract_dir = dest_path
        else:
            extract_dir = dest_path.parent
            dest_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        dest_path = None
        extract_dir = path.parent

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

        # Detect archive type by magic bytes
        with open(tmp_path, 'rb') as f:
            magic = f.read(4)

        is_gzip = magic[:2] == b'\x1f\x8b'
        is_zstd = magic == b'\x28\xb5\x2f\xfd'
        is_lz4 = magic == b'\x04\x22\x4d\x18'
        # Check for plain tar (magic at offset 257)
        is_plain_tar = False
        if not is_gzip and not is_zstd and not is_lz4:
            with open(tmp_path, 'rb') as f:
                f.seek(257)
                is_plain_tar = f.read(5) == b'ustar'

        if is_gzip:
            with tarfile.open(tmp_path, 'r:gz') as tar:
                folder = tar.getnames()[0].split('/')[0]
                tar.extractall(path=extract_dir, filter='data')
            Path(tmp_path).unlink()
            _success(f"Extracted: {extract_dir / folder} ({elapsed:.1f}s, {mbs:.0f} MiB/s)")
        elif is_zstd:
            # Decompress with zstd first
            tar_path = tmp_path + ".tar"
            subprocess.run(["zstd", "-d", "-q", "--rm", "-o", tar_path, tmp_path], check=True)
            with tarfile.open(tar_path, 'r') as tar:
                folder = tar.getnames()[0].split('/')[0]
                tar.extractall(path=extract_dir, filter='data')
            Path(tar_path).unlink()
            _success(f"Extracted: {extract_dir / folder} ({elapsed:.1f}s, {mbs:.0f} MiB/s)")
        elif is_lz4:
            # Decompress with lz4 first
            tar_path = tmp_path + ".tar"
            subprocess.run(["lz4", "-d", "-q", tmp_path, tar_path], check=True)
            Path(tmp_path).unlink()
            with tarfile.open(tar_path, 'r') as tar:
                folder = tar.getnames()[0].split('/')[0]
                tar.extractall(path=extract_dir, filter='data')
            Path(tar_path).unlink()
            _success(f"Extracted: {extract_dir / folder} ({elapsed:.1f}s, {mbs:.0f} MiB/s)")
        elif is_plain_tar:
            with tarfile.open(tmp_path, 'r') as tar:
                folder = tar.getnames()[0].split('/')[0]
                tar.extractall(path=extract_dir, filter='data')
            Path(tmp_path).unlink()
            _success(f"Extracted: {extract_dir / folder} ({elapsed:.1f}s, {mbs:.0f} MiB/s)")
        else:
            # Regular file (not archive)
            if dest_path and not dest_path.is_dir():
                out_path = dest_path
            else:
                out_path = extract_dir / path.stem.removesuffix('.tar')
                if out_path.exists():
                    out_path = out_path.with_stem(f"{out_path.stem}_{_suuid()}")
            Path(tmp_path).rename(out_path)
            _success(f"Decrypted: {out_path} ({elapsed:.1f}s, {mbs:.0f} MiB/s)")
    except Exception as e:
        Path(tmp_path).unlink(missing_ok=True)
        _error(f"Decrypt failed: {e}")

    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: ./terces file <enc|dec> <path> [dest]", file=sys.stderr)
        sys.exit(1)
    cmd, file_path = sys.argv[1], sys.argv[2]
    dest = sys.argv[3] if len(sys.argv) > 3 else None
    if cmd in ("enc", "e"):
        encrypt_file(file_path, dest)
    elif cmd in ("dec", "d"):
        decrypt_file(file_path, dest)
    else:
        _error(f"Unknown: {cmd}")
