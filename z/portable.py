# portable.py - bootstrap u2f_mappings on new machines
# Usage: python -B z/portable.py [export|import]
# Uses PIN-based encryption so mappings aren't plaintext on USB
import sys
import os
import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from gnilux import CFG, VERSION, _success

DATA_DIR = f".d/terces-{VERSION}"
BOOTSTRAP_FILE = f"{DATA_DIR}/.mappings.trcs"

def derive_key(pin: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(pin)

if len(sys.argv) < 2 or sys.argv[1] not in ("export", "import"):
    print("Usage: portable export | import")
    sys.exit(1)

if sys.argv[1] == "export":
    pin = getpass.getpass("PIN: ").encode()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(pin, salt)

    with open(CFG["mappings_file"]) as f:
        mappings = f.read().encode()

    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, mappings, None)

    os.makedirs(DATA_DIR, exist_ok=True)
    with open(BOOTSTRAP_FILE, "wb") as f:
        f.write(salt + nonce + ciphertext)
    _success(f"Exported to {BOOTSTRAP_FILE}")

elif sys.argv[1] == "import":
    pin = getpass.getpass("PIN: ").encode()

    with open(BOOTSTRAP_FILE, "rb") as f:
        data = f.read()

    salt, nonce, ciphertext = data[:16], data[16:28], data[28:]
    key = derive_key(pin, salt)

    cipher = AESGCM(key)
    mappings = cipher.decrypt(nonce, ciphertext, None)
    print(mappings.decode(), end="")

####
# Workflow:
# ./terces portable export
# Enter PIN (can be same as FIDO2 key PIN)
# Copy TERCES folder to USB
#
# On new machine:
# ./terces portable import | sudo tee /etc/u2f_mappings
# Enter same PIN
# ./terces unlock  # Should work now