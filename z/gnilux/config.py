# config.py - Loads the .cfg as a JSON file and conditionally dev mode cfg
import json
from json import JSONDecodeError
from pathlib import Path
from .handlers import _error

dev_mode = ""
_cfg_file = Path(__file__).parents[2] / f"terces.cfg{dev_mode}"

def load_config() -> dict:
    """Load config from terces.cfg, fallback to defaults"""
    defaults = {"mappings_file": "/etc/u2f_mappings", "rp_id": None, "device_index": None, "compression": "zstd"}
    try:
        if _cfg_file.exists():
            with open(_cfg_file) as f:
                return {**defaults, **json.load(f)}
        else:
            print('Config file not found.')
    except JSONDecodeError:
        _error("Config file borken")

    return defaults

CFG = load_config()
