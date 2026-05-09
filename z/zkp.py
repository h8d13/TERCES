#!/usr/bin/env python3
"""
ZKP CLI - Schnorr ZKP backed by FIDO2 hmac-secret.
Server-nonce challenged, time-bound. See tests/zkp-server for remote verifier.
"""
import sys
import json
import os
import secrets

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gnilux.chapo import U2FKey
from gnilux.config import CFG
from gnilux.nzkp import SchnorrZKP, derive_key_scrypt, check_entropy, DEFAULT_TTL
from gnilux.handlers import _error, _success, _debug

ZKP_VAULT_KEY = "zkp:keypair"


def _auth():
    return U2FKey(
        mappings_file=CFG["mappings_file"],
        rp_id=CFG["rp_id"],
        device_index=CFG["device_index"],
    )


def _load_keypair(auth):
    blob = auth.decrypt_secret(ZKP_VAULT_KEY)
    if not blob:
        _error(f"No {ZKP_VAULT_KEY} found. Run 'terces zkp init' first.")
    return json.loads(blob)


def cmd_init():
    """Derive Schnorr keypair from FIDO2 hmac-secret. Stores pubkey + salt in vault."""
    print("Initializing Schnorr ZKP keypair...")
    auth = _auth()

    fido_secret = auth.get_zkp_secret()
    derived_key, salt_hex = derive_key_scrypt(fido_secret)

    bits, ok, warning = check_entropy(derived_key)
    _debug(f"Derived key entropy: {bits:.1f} bits")
    if warning:
        print(warning)
    if not ok:
        _error("Insufficient entropy")

    zkp = SchnorrZKP()
    public_key = zkp.generate_pubkey(derived_key)

    auth.encrypt_secret(
        ZKP_VAULT_KEY,
        json.dumps({"public_key": str(public_key), "salt": salt_hex}),
        "ZKP keypair (RFC 3526 Group 14)",
    )
    _success("ZKP keypair initialized")


def cmd_prove(nonce, ttl=DEFAULT_TTL):
    """Generate proof bound to server-issued nonce."""
    auth = _auth()
    keypair = _load_keypair(auth)

    fido_secret = auth.get_zkp_secret()
    derived_key, _ = derive_key_scrypt(fido_secret, salt=keypair["salt"])

    zkp = SchnorrZKP()
    proof = zkp.prove(derived_key, nonce, ttl=ttl)
    print(json.dumps(proof))


def cmd_verify(proof_json, nonce):
    """Local self-verify against vault pubkey. Mostly for testing."""
    auth = _auth()
    keypair = _load_keypair(auth)
    public_key = int(keypair["public_key"])

    try:
        proof = json.loads(proof_json)
    except json.JSONDecodeError:
        _error("Invalid JSON proof")

    valid, msg = SchnorrZKP().verify(public_key, proof, nonce)
    if valid:
        _success(f"VALID: {msg}")
    else:
        _error(f"INVALID: {msg}")


def cmd_info():
    auth = _auth()
    keypair = _load_keypair(auth)
    pk = keypair["public_key"]
    print(f"Group: RFC 3526 Group 14 (2048-bit MODP)")
    print(f"Salt:  {keypair['salt']}")
    print(f"Pubkey: {pk[:64]}...{pk[-16:]}")


def cmd_export():
    """Print pubkey JSON for the remote verifier."""
    auth = _auth()
    keypair = _load_keypair(auth)
    print(json.dumps({"public_key": keypair["public_key"]}))


def cmd_verify_remote(proof_json, pubkey_json, nonce):
    """Verify proof against an exported pubkey. No FIDO2 / vault needed."""
    try:
        proof = json.loads(proof_json)
        pubkey_data = json.loads(pubkey_json)
    except json.JSONDecodeError:
        _error("Invalid JSON")

    public_key = int(pubkey_data["public_key"])
    valid, msg = SchnorrZKP().verify(public_key, proof, nonce)
    if valid:
        _success(f"VALID: {msg}")
    else:
        _error(f"INVALID: {msg}")


def cmd_nonce():
    """Generate a fresh server-style nonce. Useful for local self-tests."""
    print(secrets.token_hex(16))


def main():
    if len(sys.argv) < 2:
        print("ZKP - Schnorr proof over FIDO2 hmac-secret")
        print()
        print("Commands:")
        print("  init                              - Derive keypair, store pubkey")
        print("  prove <nonce> [ttl]               - Generate proof for server-issued nonce")
        print("  verify '<proof>' <nonce>          - Self-verify against vault pubkey")
        print("  verify-remote '<proof>' '<pk>' <nonce>")
        print("                                    - Verify with exported pubkey only")
        print("  info                              - Show stored pubkey info")
        print("  export                            - Print pubkey JSON")
        print("  nonce                             - Generate a random nonce (testing)")
        return

    cmd = sys.argv[1]

    if cmd == "init":
        cmd_init()
    elif cmd == "prove":
        if len(sys.argv) < 3:
            _error("Usage: zkp prove <nonce> [ttl]")
        ttl = int(sys.argv[3]) if len(sys.argv) > 3 else DEFAULT_TTL
        cmd_prove(sys.argv[2], ttl)
    elif cmd == "verify":
        if len(sys.argv) < 4:
            _error("Usage: zkp verify '<proof>' <nonce>")
        cmd_verify(sys.argv[2], sys.argv[3])
    elif cmd == "verify-remote":
        if len(sys.argv) < 5:
            _error("Usage: zkp verify-remote '<proof>' '<pubkey>' <nonce>")
        cmd_verify_remote(sys.argv[2], sys.argv[3], sys.argv[4])
    elif cmd == "info":
        cmd_info()
    elif cmd == "export":
        cmd_export()
    elif cmd == "nonce":
        cmd_nonce()
    else:
        _error(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()
