# setup.py - register FIDO2 key to mappings file
import os
import subprocess
import socket
from gnilux import CFG, _success, _error, uid, who_dat

if uid != 0:
    _error("Run with sudo")
    exit(1)

mappings = CFG["mappings_file"]
rp_id = CFG["rp_id"] or f"pam://{socket.gethostname()}"
user = who_dat(uid)

# Build command with rp_id
cmd = ["pamu2fcfg", "-u", user, "-o", rp_id]

subprocess.run(["touch", mappings], check=True)
result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
    with open(mappings, "a") as f:
        f.write(result.stdout)
    os.chmod(mappings, 0o600)
    _success(f"Registered with rp_id: {rp_id}")
    _success(f"Mappings: {mappings}. Run: ./terces unlock")
else:
    _error(f"pamu2fcfg failed: {result.stderr}")
