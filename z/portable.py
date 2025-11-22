# portable.py - bootstrap u2f_mappings on new machines
# Usage: python -B z/portable.py [export|import]
import sys
from gnilux import CFG, U2FKey, _success, _error

auth = U2FKey(mappings_file=CFG["mappings_file"], rp_id=CFG["rp_id"])
BOOTSTRAP_NAME = "_mappings"

if len(sys.argv) < 2 or sys.argv[1] not in ("export", "import"):
    print("Usage: portable export | import")
    sys.exit(1)

if sys.argv[1] == "export":
    # Encrypt current mappings file for portability
    if auth.authenticate():
        with open(CFG["mappings_file"]) as f:
            mappings = f.read()
        auth.encrypt_secret(BOOTSTRAP_NAME, mappings, "u2f_mappings bootstrap")
        _success("Mappings exported. Copy whole folder to USB.")
    else:
        _error("Auth failed")

elif sys.argv[1] == "import":
    # Decrypt mappings - for pipe | sudo tee /etc/u2f_mappings
    if auth.authenticate():
        mappings = auth.decrypt_secret(BOOTSTRAP_NAME)
        if mappings:
            print(mappings, end="")
    else:
        _error("Auth failed")

####
# Workflow:
# ./terces portable export
# Copy TERCES folder to USB
#
# On new machine:
# ./terces portable import | sudo tee /etc/u2f_mappings
# ./terces unlock  # Should work now