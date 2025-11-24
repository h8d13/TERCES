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
            # Count existing ssh entries for index
            index = auth._load_index()
            ssh_count = sum(1 for v in index.values() if v.get("description", "").startswith("ssh"))
            auth.encrypt_secret(
                name=f"ssh:{name}",
                plaintext=pubkey,
                description=f"ssh{ssh_count}"
            )
        return True
    else:
        _error("SSH key generation failed")
        return False


def test(provider: str):
    """Test which SSH keys are offered to a provider"""
    # Add git@ prefix if not present
    if not provider.startswith("git@"):
        provider = f"git@{provider}"

    result = subprocess.run(
        ["ssh", "-vT", provider],
        capture_output=True,
        text=True
    )

    # Grep for Offering lines (in stderr)
    for line in result.stderr.split('\n'):
        if "Offering" in line:
            print(line.strip())


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./terces ssh <name> [--no-res] | test <provider>")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "test":
        if len(sys.argv) < 3:
            _error("Missing provider")
            print("Usage: ./terces ssh test github.com")
            sys.exit(1)
        test(sys.argv[2])
    else:
        name = cmd
        resident = "--no-res" not in sys.argv
        generate(name, resident=resident)
