# config.py - Loads the .cfg as a JSON file and conditionally dev mode cfg
import json
from json import JSONDecodeError
from pathlib import Path
from .handlers import _error
from .admin import uid, is_elevated

dev_mode = ""
_cfg_file = Path(__file__).parents[2] / f"terces.cfg{dev_mode}"

# System vs user mappings path
_SYSTEM_MAPPINGS = "/etc/u2f_mappings"
_USER_MAPPINGS = "~/.config/Yubico/u2f_keys"

def load_config() -> dict:
    """Load config from terces.cfg, fallback to defaults"""
    elevated = is_elevated(uid)
    default_mappings = _SYSTEM_MAPPINGS if elevated else _USER_MAPPINGS

    defaults = {"mappings_file": default_mappings, "rp_id": None, "device_index": None, "key_index": 0, "compression": "zstd"}
    try:
        if _cfg_file.exists():
            with open(_cfg_file) as f:
                cfg = {**defaults, **json.load(f)}
                # Override mappings based on elevation
                cfg["mappings_file"] = _SYSTEM_MAPPINGS if elevated else _USER_MAPPINGS
                return cfg
        else:
            print('Config file not found.')
    except JSONDecodeError:
        _error("Config file borken")

    return defaults

CFG = load_config()
