#!/usr/bin/env python3
"""
Quick testing tool for NZKP without FIDO2.
For testing only. Use zkp.py for production.
"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(__file__))
from gnilux.nzkp import PrimeTimeTZKP

if len(sys.argv) < 2:
    print("Usage:")
    print("  python3 z/nzkp_test.py keygen <secret>")
    print("  python3 z/nzkp_test.py prove <secret>")
    sys.exit(1)

cmd = sys.argv[1]

if cmd == "keygen":
    secret = int(sys.argv[2])
    zkp = PrimeTimeTZKP()
    _, _, public_key = zkp.generate_keypair(secret)
    print(f"Public (full): {public_key}")

elif cmd == "prove":
    secret = int(sys.argv[2])
    zkp = PrimeTimeTZKP()
    proof = zkp.prove_knowledge(secret)
    print(json.dumps(proof, indent=2))

else:
    print(f"Unknown command: {cmd}")
