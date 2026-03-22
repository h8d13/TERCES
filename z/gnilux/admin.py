# admin.py returns basic system info and holds essentials vars
import os
import uuid
from pathlib import Path

_version_file = Path(__file__).parent.parent.parent / "version"
VERSION = _version_file.read_text().strip() if _version_file.exists() else "0000"

uid = int(os.getuid())

def is_elevated(uid):
    if uid == 0:
        return True
    else:
        return False

def who_dat(uid):
    if is_elevated(uid):
        username = os.getenv("SUDO_USER", "root")
    else:
        username = os.getenv("USER")

    return username

username = who_dat(uid)

def _random(x):
    return os.urandom(x)

def _suuid():
    short_uuid = str(uuid.uuid4())[:8]
    return short_uuid
