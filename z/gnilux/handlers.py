# handlers.py - Colored output and all directed to stderr because we need pipes
# _error exits
# _debug (can be extended to be turned off)
# _suceess and _nf_warn just print
import sys
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

def _success(message):
    print(f"{GREEN}[SUCCESS]{RESET} {message}", file=sys.stderr)

def _nf_warn(message):
    print(f"{YELLOW}[WARNING]{RESET} {message}", file=sys.stderr)

def _error(message):
    print(f"{RED}[ERROR]{RESET} {message}", file=sys.stderr)
    sys.exit(1)

def _debug(message):
    print(f"{BLUE}[DEBUG]{RESET} {message}", file=sys.stderr)

