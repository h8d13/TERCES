import sys

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
BLUE = "\033[94m"
RESET = "\033[0m"

def _success(message):
    print(f"{GREEN}[SUCCESS]{RESET} {message}", file=sys.stderr)

def _error(message):
    print(f"{RED}[ERROR]{RESET} {message}", file=sys.stderr)
    sys.exit(1)

def _nf_warn(message):
    print(f"{YELLOW}[WARNING]{RESET} {message}", file=sys.stderr)

def _debug(message):
    print(f"{BLUE}[DEBUG]{RESET} {message}", file=sys.stderr)

