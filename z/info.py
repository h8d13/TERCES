#info.py
import sys
from gnilux import (
    CFG,
    info,
)


filter_pattern = sys.argv[1] if len(sys.argv) > 1 else None
info(filter_pattern=filter_pattern, device_index=CFG["device_index"])
