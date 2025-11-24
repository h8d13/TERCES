#!/usr/bin/env python3
"""
ZKP CLI - Zero-Knowledge Proof authentication backed by FIDO2
"""

import sys
import json
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gnilux.chapo import U2FKey
from gnilux.nzkp import (
    PrimeTimeTZKP,
    derive_key_scrypt,
    check_entropy,
)
from gnilux.handlers import _error, _success, _debug

ZKP_VAULT_KEY = "zkp:keypair"

def cmd_init(bits=2048):
    """Initialize ZKP keypair derived from FIDO2 hmac-secret"""
    print(f"Initializing {bits}-bit ZKP keypair...")

    auth = U2FKey()

    # Derive secret from FIDO2 using dedicated salt
    fido_secret = auth.get_zkp_secret()

    # Additional hardening with scrypt
    derived_key, salt_hex = derive_key_scrypt(fido_secret)

    # Check entropy
    entropy_bits, is_ok, warning = check_entropy(derived_key)
    _debug(f"Derived key entropy: {entropy_bits:.1f} bits")
    if warning:
        print(warning)

    # Generate keypair
    zkp = PrimeTimeTZKP(bits)
    _, _, public_key = zkp.generate_keypair(derived_key)

    # Store public key + salt + bits in vault
    keypair_data = json.dumps({
        "public_key": str(public_key),
        "salt": salt_hex,
        "bits": bits,
    })

    auth.encrypt_secret(ZKP_VAULT_KEY, keypair_data, "ZKP public key")
    _success(f"ZKP keypair initialized ({bits}-bit)")
    print(f"Public key stored in vault as '{ZKP_VAULT_KEY}'")


def cmd_prove(ttl=300):
    """Generate a time-bound ZKP proof"""
    auth = U2FKey()

    # Load stored keypair info
    keypair_json = auth.decrypt_secret(ZKP_VAULT_KEY)
    if not keypair_json:
        _error(f"No {ZKP_VAULT_KEY} found. Run 'terces zkp init' first.")
        return

    keypair = json.loads(keypair_json)
    bits = keypair.get("bits", 2048)
    salt_hex = keypair["salt"]

    # Re-derive the secret (requires FIDO2 touch)
    fido_secret = auth.get_zkp_secret()
    derived_key, _ = derive_key_scrypt(fido_secret, salt=salt_hex)

    # Generate proof
    zkp = PrimeTimeTZKP(bits)
    zkp.proof_validity_seconds = ttl

    proof = zkp.prove_knowledge(derived_key)
    proof["bits"] = bits
    proof["ttl"] = ttl

    print(json.dumps(proof, indent=2))


def cmd_verify(proof_json):
    """Verify a ZKP proof (no FIDO2 required, only public key)"""
    auth = U2FKey()

    # Load stored public key
    keypair_json = auth.decrypt_secret(ZKP_VAULT_KEY)
    if not keypair_json:
        _error(f"No {ZKP_VAULT_KEY}. Run 'terces zkp init' first.")
        return

    keypair = json.loads(keypair_json)
    public_key = int(keypair["public_key"])
    bits = keypair.get("bits", 2048)

    # Parse proof
    try:
        proof = json.loads(proof_json)
    except json.JSONDecodeError:
        _error("Invalid JSON proof")
        return

    # Verify
    zkp = PrimeTimeTZKP(bits)
    valid, message = zkp.verify_proof(public_key, proof)

    if valid:
        _success(f"VALID: {message}")
        import time
        remaining = proof.get("ttl", 300) - (int(time.time()) - proof["timestamp"])
        if remaining > 0:
            print(f"Expires in {remaining}s")
        else:
            print("(expired but signature valid)")
    else:
        _error(f"INVALID: {message}")


def cmd_info():
    """Show stored ZKP public key info"""
    auth = U2FKey()

    keypair_json = auth.decrypt_secret(ZKP_VAULT_KEY)
    if not keypair_json:
        _error(f"No {ZKP_VAULT_KEY} found. Run 'terces zkp init' first.")
        return

    keypair = json.loads(keypair_json)
    print(f"Bits: {keypair.get('bits', 2048)}")
    print(f"Salt: {keypair['salt']}")
    print(f"Public key: {keypair['public_key'][:64]}...")


def cmd_export():
    """Export public key for remote verification"""
    auth = U2FKey()

    keypair_json = auth.decrypt_secret(ZKP_VAULT_KEY)
    if not keypair_json:
        _error(f"No {ZKP_VAULT_KEY} found. Run 'terces zkp init' first.")
        return

    keypair = json.loads(keypair_json)
    export_data = {
        "public_key": keypair["public_key"],
        "bits": keypair.get("bits", 2048),
    }
    print(json.dumps(export_data))


def cmd_verify_remote(proof_json, pubkey_json):
    """Verify proof against exported public key (fully offline)"""
    try:
        proof = json.loads(proof_json)
        pubkey_data = json.loads(pubkey_json)
    except json.JSONDecodeError:
        _error("Invalid JSON")
        return

    public_key = int(pubkey_data["public_key"])
    bits = pubkey_data.get("bits", 2048)

    zkp = PrimeTimeTZKP(bits)
    valid, message = zkp.verify_proof(public_key, proof)

    if valid:
        _success(f"VALID: {message}")
    else:
        _error(f"INVALID: {message}")


def main():
    if len(sys.argv) < 2:
        print("ZKP - Zero-Knowledge Proof Authentication")
        print()
        print("Commands:")
        print("  init [bits]           - Initialize keypair (2048/3072/4096)")
        print("  prove [ttl]           - Generate time-bound proof")
        print("  verify '<proof>'      - Verify proof")
        print("  info                  - Show public key info")
        print("  export                - Export public key for remote use")
        print("  verify-remote '<proof>' '<pubkey>' - Verify without vault")
        return

    cmd = sys.argv[1]

    if cmd == "init":
        bits = int(sys.argv[2]) if len(sys.argv) > 2 else 2048
        if bits not in [2048, 3072, 4096]:
            _error("Bits must be 2048, 3072, or 4096")
            return
        cmd_init(bits)

    elif cmd == "prove":
        ttl = int(sys.argv[2]) if len(sys.argv) > 2 else 300
        cmd_prove(ttl)

    elif cmd == "verify":
        if len(sys.argv) < 3:
            _error("Usage: zkp verify '<proof_json>'")
            return
        cmd_verify(sys.argv[2])

    elif cmd == "info":
        cmd_info()

    elif cmd == "export":
        cmd_export()

    elif cmd == "verify-remote":
        if len(sys.argv) < 4:
            _error("Usage: zkp verify-remote '<proof_json>' '<pubkey_json>'")
            return
        cmd_verify_remote(sys.argv[2], sys.argv[3])

    else:
        _error(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
