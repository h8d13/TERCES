# ssh.py - FIDO2-backed SSH key generation
import sys
import subprocess
from pathlib import Path

from gnilux import (
    CFG,
    U2FKey,
    username,
    uid,
    is_elevated,
    _success,
    _error,
    _debug,
)

SSH_DIR = Path(f"~{username}/.ssh").expanduser()
DEFAULT_KEY_TYPE = "ed25519-sk"


def generate(name: str, resident: bool = True, key_type: str = DEFAULT_KEY_TYPE):
    """
    Generate FIDO2-backed SSH key after terces authentication.

    Args:
        name: Key identifier (used in filename and application tag)
        resident: Store credential on device (recommended)
        key_type: ed25519-sk or ecdsa-sk
    """
    auth = U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"]
    )

    if not auth.authenticate():
        _error("Auth failed - SSH key generation blocked")
        return False

    _success("Auth OK - generating SSH key")

    key_path = SSH_DIR / f"id_{name}_sk"

    if key_path.exists():
        _error(f"Key already exists: {key_path}")
        print("Use a different name or remove existing key first.")
        return False

    cmd = [
        "ssh-keygen",
        "-t", key_type,
        "-O", f"application=ssh:{name}",
        "-f", str(key_path),
    ]

    if resident:
        cmd.extend(["-O", "resident"])

    # Run as original user if elevated
    if is_elevated(uid):
        cmd = ["sudo", "-u", username] + cmd

    _debug(f"Running: {' '.join(cmd)}")

    result = subprocess.run(cmd)

    if result.returncode == 0:
        _success(f"SSH key generated: {key_path}")
        _success(f"Public key: {key_path}.pub")

        # Store public key in terces vault
        pub_path = Path(f"{key_path}.pub")
        if pub_path.exists():
            pubkey = pub_path.read_text().strip()
            auth.encrypt_secret(
                name=f"ssh:{name}",
                plaintext=pubkey,
                description=f"ssh-key:{name}"
            )
        return True
    else:
        _error("SSH key generation failed")
        return False


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./terces ssh <name> [--no-res]")
        sys.exit(1)

    name = sys.argv[1]
    resident = "--no-res" not in sys.argv
    generate(name, resident=resident)
