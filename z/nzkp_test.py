#!/usr/bin/env python3
"""
NZKP smoke test without FIDO2. Uses a literal int as the secret.
For protocol-level testing only. Use zkp.py for real flow.
"""
import sys
import os
import json
import secrets

sys.path.insert(0, os.path.dirname(__file__))
from gnilux.nzkp import SchnorrZKP

if len(sys.argv) < 2:
    print("Usage:")
    print("  python3 z/nzkp_test.py keygen <secret_int>")
    print("  python3 z/nzkp_test.py prove <secret_int> [nonce]")
    print("  python3 z/nzkp_test.py roundtrip <secret_int>")
    sys.exit(1)

cmd = sys.argv[1]
zkp = SchnorrZKP()

if cmd == "keygen":
    secret = int(sys.argv[2])
    print(f"Public key: {zkp.generate_pubkey(secret)}")

elif cmd == "prove":
    secret = int(sys.argv[2])
    nonce = sys.argv[3] if len(sys.argv) > 3 else secrets.token_hex(16)
    print(json.dumps(zkp.prove(secret, nonce)))

elif cmd == "roundtrip":
    secret = int(sys.argv[2])
    pk = zkp.generate_pubkey(secret)
    nonce = secrets.token_hex(16)
    proof = zkp.prove(secret, nonce)
    valid, msg = zkp.verify(pk, proof, nonce)
    print(f"Roundtrip: {msg}")
    sys.exit(0 if valid else 1)

else:
    print(f"Unknown command: {cmd}")
    sys.exit(1)
