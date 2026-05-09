"""
Schnorr ZKP over RFC 3526 MODP Group 14 (2048-bit).
Time-bound, server-nonce challenged. Replay-resistant when server tracks issued nonces.
"""
import hashlib
import secrets
import time
import os
import math
from collections import Counter

# RFC 3526 Group 14 (2048-bit MODP). Public constant.
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
    "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
    "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
    "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
    "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
    "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFF"
    "FFFFFFFF"
)
P = int(P_HEX, 16)
G = 2

DEFAULT_TTL = 300


def check_entropy(data):
    """Shannon entropy. Returns (bits, ok, warning_or_None)."""
    MIN_BITS = 64
    WARN_BITS = 80

    if isinstance(data, int):
        if data <= 0:
            return 0, False, "Secret must be positive"
        data_bytes = data.to_bytes((data.bit_length() + 7) // 8, "big")
    elif isinstance(data, str):
        data_bytes = data.encode()
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        return 0, False, "Unsupported data type"

    if not data_bytes:
        return 0, False, "Empty input"

    freq = Counter(data_bytes)
    total = len(data_bytes)
    per_byte = -sum((c / total) * math.log2(c / total) for c in freq.values())
    bits = per_byte * len(data_bytes)
    if isinstance(data, int):
        bits = min(bits, data.bit_length())

    if bits < MIN_BITS:
        return bits, False, f"CRITICAL: Entropy {bits:.1f} bits < {MIN_BITS} min"
    if bits < WARN_BITS:
        return bits, True, f"WARNING: Entropy {bits:.1f} bits < {WARN_BITS} recommended"
    return bits, True, None


def derive_key_scrypt(password, salt=None, n=2**14, r=8, p=1, dklen=32):
    """scrypt KDF. Returns (key_int, salt_hex)."""
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt) if len(salt) == 32 else salt.encode()

    if isinstance(password, int):
        password = str(password).encode()
    elif isinstance(password, str):
        password = password.encode()

    derived = hashlib.scrypt(password, salt=salt, n=n, r=r, p=p, dklen=dklen)
    return int.from_bytes(derived, "big"), salt.hex()


class SchnorrZKP:
    """Schnorr proof of knowledge of discrete log over RFC 3526 Group 14."""

    def __init__(self):
        self.p = P
        self.g = G
        self.q = P - 1

    def _hash(self, *args):
        h = hashlib.sha256()
        for a in args:
            h.update(str(a).encode())
        return int.from_bytes(h.digest(), "big") % self.q

    def generate_pubkey(self, secret):
        return pow(self.g, secret % self.q, self.p)

    def prove(self, secret, nonce, ttl=DEFAULT_TTL):
        """Generate proof binding to server-issued nonce + timestamp."""
        x = secret % self.q
        r = secrets.randbelow(self.q - 1) + 1
        commitment = pow(self.g, r, self.p)
        timestamp = int(time.time())
        challenge = self._hash(self.g, commitment, timestamp, nonce)
        response = (r + challenge * x) % self.q
        return {
            "commitment": str(commitment),
            "response": str(response),
            "timestamp": timestamp,
            "nonce": nonce,
            "ttl": ttl,
        }

    def verify(self, public_key, proof, expected_nonce):
        """Verify proof. Returns (valid, message)."""
        if proof.get("nonce") != expected_nonce:
            return False, "Nonce mismatch"

        ttl = proof.get("ttl", DEFAULT_TTL)
        age = int(time.time()) - proof["timestamp"]
        if age > ttl:
            return False, f"Proof expired ({age}s > {ttl}s)"
        if age < -30:
            return False, "Proof timestamp in future"

        try:
            commitment = int(proof["commitment"])
            response = int(proof["response"])
        except (KeyError, ValueError):
            return False, "Malformed proof"

        if not (1 < commitment < self.p):
            return False, "Commitment out of range"

        challenge = self._hash(self.g, commitment, proof["timestamp"], expected_nonce)
        left = pow(self.g, response, self.p)
        right = (commitment * pow(public_key, challenge, self.p)) % self.p

        if left == right:
            return True, "Valid proof"
        return False, "Invalid proof"
