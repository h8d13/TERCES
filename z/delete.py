# delete.py - Delete a stored secret
import sys
import os

from gnilux import CFG, U2FKey, _success, _error


def delete_secret(name: str):
    """Delete a secret by name (index entry stays)"""
    auth = U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"]
    )

    filename = auth._derive_filename(name)

    if not os.path.exists(filename):
        _error(f"No secret found: {name}")
        return False

    os.remove(filename)
    _success(f"Deleted: {name}")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./terces delete <name>")
        sys.exit(1)

    name = sys.argv[1]
    delete_secret(name)
