import json
from pathlib import Path

_cfg_file = Path(__file__).parent.parent.parent / "terces.cfg"

def load_config() -> dict:
    """Load config from terces.cfg, fallback to defaults"""
    defaults = {"mappings_file": "/etc/u2f_mappings"}
    if _cfg_file.exists():
        with open(_cfg_file) as f:
            return {**defaults, **json.load(f)}
    return defaults

CFG = load_config()
