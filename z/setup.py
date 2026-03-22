# setup.py - register FIDO2 key to mappings file
import os
import subprocess
import socket
from gnilux import CFG, _success, _error, uid, who_dat

mappings = os.path.expanduser(CFG["mappings_file"])
rp_id = CFG["rp_id"] or f"pam://{socket.gethostname()}"
user = who_dat(uid)

# Build command with options from config
cmd = ["pamu2fcfg", "-u", user, "-o", rp_id]

# Key type: ES256 (default), EDDSA, or RS256
if CFG.get("key_type"):
    cmd.extend(["-t", CFG["key_type"]])

# Resident/discoverable credential (stored on device - good for portability)
if CFG.get("resident"):
    cmd.append("-r")

# Require PIN verification during auth
if CFG.get("pin_verification"):
    cmd.append("-N")

# Require user verification during auth
if CFG.get("user_verification"):
    cmd.append("-V")

# Debug output
if CFG.get("debug"):
    cmd.append("-d")

# Ensure parent directory exists
os.makedirs(os.path.dirname(mappings), exist_ok=True)

# Warn if mappings already exist
write_mode = "w"
if os.path.exists(mappings) and os.path.getsize(mappings) > 0:
    print(f"Mappings already exist: {mappings}")
    choice = input("[O]verwrite / [A]ppend / [C]ancel? ").strip().lower()
    if choice == 'o':
        write_mode = "w"
    elif choice == 'a':
        write_mode = "a"
    else:
        print("Aborted.")
        exit(0)

result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
    with open(mappings, write_mode) as f:
        f.write(result.stdout)
    os.chmod(mappings, 0o600)
    _success(f"Registered with rp_id: {rp_id}")
    _success(f"Mappings: {mappings}. Run: ./terces unlock")
else:
    _error(f"pamu2fcfg failed: {result.stderr}")
