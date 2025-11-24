# vault.py - List stored secrets
from gnilux import CFG, U2FKey, _success, _error

def list_secrets():
    """List all stored secrets from the index"""
    auth = U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"]
    )

    index = auth._load_index()

    if not index:
        print("No secrets stored.")
        return

    print("Stored secrets:")
    print("-" * 40)
    for uid, data in index.items():
        desc = data.get("description", "")
        time = data.get("time", "")[:10]  # date only
        print(f"  {desc:<20} ({time})")


if __name__ == "__main__":
    list_secrets()
