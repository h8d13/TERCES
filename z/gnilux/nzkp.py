import sys
import json
import hashlib
import secrets
import time
import os
import math
import re
from pathlib import Path
from collections import Counter
from cryptography.hazmat.primitives.serialization import load_pem_parameters

####
# Time-bound 5 Minute default
# Shannon entropy calc
# Scrypt derivation of key
# Trit encoder
# RFC 3526 from .pem
####

PEM_FILE = Path(__file__).parent / ".pem"

def load_rfc3526(bits=2048):
    """Load RFC 3526 DH parameters from .pem file"""
    if not PEM_FILE.exists():
        raise FileNotFoundError(f"Missing {PEM_FILE}")

    content = PEM_FILE.read_text()
    # Find block tagged with # <bits> comment followed by PEM (X9.42 or PKCS3 format)
    pattern = rf"# {bits}\n(-----BEGIN (?:X9\.42 )?DH PARAMETERS-----.*?-----END (?:X9\.42 )?DH PARAMETERS-----)"
    match = re.search(pattern, content, re.DOTALL)

    if not match:
        available = re.findall(r"^# (\d+)$", content, re.MULTILINE)
        raise ValueError(f"No {bits}-bit params. Available: {available}")

    params = load_pem_parameters(match.group(1).encode())
    return params.parameter_numbers().p, params.parameter_numbers().g 


def check_entropy(data):
    """
    Calculate Shannon entropy of input data.
    Returns (entropy_bits, is_acceptable, warning_msg)
    """
    MIN_ENTROPY_BITS = 64
    WARN_ENTROPY_BITS = 80

    if isinstance(data, int):
        if data <= 0:
            return 0, False, "Secret must be positive"
        bit_length = data.bit_length()
        data_bytes = data.to_bytes((bit_length + 7) // 8, 'big')
    elif isinstance(data, str):
        data_bytes = data.encode()
    elif isinstance(data, bytes):
        data_bytes = data
    else:
        return 0, False, "Unsupported data type"

    if len(data_bytes) == 0:
        return 0, False, "Empty input"

    freq = Counter(data_bytes)
    total = len(data_bytes)
    entropy_per_byte = -sum((c/total) * math.log2(c/total) for c in freq.values())
    entropy_bits = entropy_per_byte * len(data_bytes)

    if isinstance(data, int):
        entropy_bits = min(entropy_bits, data.bit_length())

    is_acceptable = entropy_bits >= MIN_ENTROPY_BITS

    if entropy_bits < MIN_ENTROPY_BITS:
        warning = f"CRITICAL: Entropy {entropy_bits:.1f} bits < {MIN_ENTROPY_BITS} min"
    elif entropy_bits < WARN_ENTROPY_BITS:
        warning = f"WARNING: Entropy {entropy_bits:.1f} bits < {WARN_ENTROPY_BITS} recommended"
    else:
        warning = None

    return entropy_bits, is_acceptable, warning


def derive_key_scrypt(password, salt=None, n=2**14, r=8, p=1, dklen=32):
    """
    Derive a cryptographic key from password using scrypt.
    Returns (derived_key_int, salt_hex)
    """
    if salt is None:
        salt = os.urandom(16)
    elif isinstance(salt, str):
        salt = bytes.fromhex(salt) if len(salt) == 32 else salt.encode()

    if isinstance(password, int):
        password = str(password).encode()
    elif isinstance(password, str):
        password = password.encode()

    derived = hashlib.scrypt(
        password,
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen
    )

    return int.from_bytes(derived, 'big'), salt.hex()

class TZKP:
    def __init__(self, trits=None):
        self.trits = trits or []
    
    @classmethod
    def from_int(cls, n):
        if n == 0:
            return cls([0])
        
        trits = []
        while n:
            if n % 3 == 0:
                trits.append(0)
                n //= 3
            elif n % 3 == 1:
                trits.append(1)
                n //= 3
            else:
                trits.append(-1)
                n = (n + 1) // 3
        
        return cls(trits)
    
    def to_int(self):
        result = 0
        for i, trit in enumerate(self.trits):
            result += trit * (3 ** i)
        return result
    
    def __str__(self):
        if not self.trits:
            return "0"
        return ''.join(str(t).replace('-1', 'T') for t in reversed(self.trits))

class PrimeTimeTZKP:
    def __init__(self, bits=2048):
        # Load RFC 3526 MODP Group from .pem
        self.p, self.g = load_rfc3526(bits)
        self.bits = bits

        # Proof validity window (5 minutes)
        self.proof_validity_seconds = 300
    
    def secure_random(self, max_val):
        return secrets.randbelow(max_val - 1) + 1
    
    def secure_hash(self, *args):
        h = hashlib.sha256()
        for arg in args:
            h.update(str(arg).encode())
        return int.from_bytes(h.digest(), 'big') % (self.p - 1)
    
    def generate_keypair(self, secret):
        secret_mod = secret % (self.p - 1)
        secret_trits = TZKP.from_int(secret_mod)
        public_key = pow(self.g, secret_mod, self.p)
        public_trits = TZKP.from_int(public_key % 6561)  # Keep trit display manageable
        return secret_trits, public_trits, public_key
    
    def prove_knowledge(self, secret):
        secret_mod = secret % (self.p - 1)
        
        # Cryptographically secure random nonce
        r = self.secure_random(self.p - 1)
        
        # Commitment using proper discrete log
        commitment = pow(self.g, r, self.p)
        
        # Add timestamp for time-bound proof
        timestamp = int(time.time())
        
        # Fiat-Shamir challenge including timestamp
        challenge = self.secure_hash(self.g, commitment, timestamp)
        
        # Response
        response = (r + challenge * secret_mod) % (self.p - 1)
        
        commit_trits = TZKP.from_int(commitment % 6561)
        
        return {
            "commit_trits": str(commit_trits),
            "commitment": str(commitment),
            "challenge": str(challenge),
            "response": str(response),
            "timestamp": timestamp
        }
    
    def generate_session_token(self, secret, user_id, nonce=None):
        """
        Generate a session token with embedded ZKP proof.

        Args:
            secret: The ZKP secret
            user_id: User identifier
            nonce: Optional nonce (auto-generated if None)

        Returns:
            Dict with token, proof, and session data
        """
        if nonce is None:
            nonce = secrets.token_hex(16)

        proof = self.prove_knowledge(secret)

        # Combine proof with session data
        combined = f"{proof['commitment']}{proof['challenge']}{user_id}{nonce}{proof['timestamp']}"
        hash_val = hashlib.sha512(combined.encode()).hexdigest()
        hash_int = int(hash_val, 16)

        # 81 trits = ~128 bits entropy
        token_int = hash_int % (3 ** 81)
        token_id = TZKP.from_int(token_int)

        return {
            "token": str(token_id),
            "proof": proof,
            "nonce": nonce,
            "user_id": user_id
        }
    
    def verify_proof(self, public_key, proof_data):
        # Check timestamp validity
        current_time = int(time.time())
        if current_time - proof_data["timestamp"] > self.proof_validity_seconds:
            return False, "Proof expired"
        
        # Convert string inputs to integers
        commitment = int(proof_data["commitment"])
        challenge = int(proof_data["challenge"])
        response = int(proof_data["response"])
        
        # Verify challenge
        expected_challenge = self.secure_hash(self.g, commitment, proof_data["timestamp"])
        if challenge != expected_challenge:
            return False, "Invalid challenge"
        
        # Verify Schnorr equation: g^response = commitment * public_key^challenge
        left = pow(self.g, response, self.p)
        right = (commitment * pow(public_key, challenge, self.p)) % self.p
        
        if left == right:
            return True, "Valid proof"
        else:
            return False, "Invalid proof"

def cmd_keygen():
    if len(sys.argv) < 3:
        print("Usage: tzkp.py keygen <secret_number>")
        return

    secret = int(sys.argv[2])

    entropy_bits, is_ok, warning = check_entropy(secret)
    print(f"Entropy: {entropy_bits:.1f} bits")
    if warning:
        print(warning)
        if not is_ok:
            print("Aborting: insufficient entropy")
            return

    zkp = PrimeTimeTZKP()
    secret_trits, public_trits, public_key = zkp.generate_keypair(secret)

    print(f"Secret: {secret} -> {secret_trits}")
    print(f"Public (trit): {public_trits}")
    print(f"Public (full): {public_key}")


def cmd_derive():
    if len(sys.argv) < 3:
        print("Usage: tzkp.py derive <password> [salt_hex]")
        return

    password = sys.argv[2]
    salt = sys.argv[3] if len(sys.argv) > 3 else None

    entropy_bits, is_ok, warning = check_entropy(password)
    print(f"Password entropy: {entropy_bits:.1f} bits")
    if warning:
        print(warning)

    derived_key, salt_hex = derive_key_scrypt(password, salt)
    print(f"Salt: {salt_hex}")
    print(f"Derived key: {derived_key}")

    zkp = PrimeTimeTZKP()
    secret_trits, public_trits, public_key = zkp.generate_keypair(derived_key)
    print(f"Public (trit): {public_trits}")
    print(f"Public (full): {public_key}")

def cmd_prove():
    if len(sys.argv) < 3:
        print("Usage: tzkp.py prove <secret_number>")
        return
    
    secret = int(sys.argv[2])
    zkp = PrimeTimeTZKP()
    
    proof = zkp.prove_knowledge(secret)
    print(json.dumps(proof, indent=2))

def cmd_session_token():
    if len(sys.argv) < 4:
        print("Usage: tzkp.py session-token <secret> <user_id> [nonce]")
        return

    secret = int(sys.argv[2])
    user_id = sys.argv[3]
    nonce = sys.argv[4] if len(sys.argv) > 4 else None
    zkp = PrimeTimeTZKP()

    result = zkp.generate_session_token(secret, user_id, nonce)
    print(json.dumps(result, indent=2))

def cmd_verify():
    if len(sys.argv) < 4:
        print("Usage: zkp verify <public_key> <proof_json>")
        return
    
    public_key = int(sys.argv[2])
    proof_json = sys.argv[3]
    
    zkp = PrimeTimeTZKP()
    proof_data = json.loads(proof_json)
    
    valid, message = zkp.verify_proof(public_key, proof_data)
    print(f"{'VALID' if valid else 'INVALID'}: {message}")

def main():
    if len(sys.argv) < 2:
        print("PTZKP - Prime Time Zero-Knowledge Proof")
        print()
        print("Commands:")
        print("  keygen <secret>              - Generate keypair (entropy checked)")
        print("  derive <password> [salt]     - Derive key via scrypt")
        print("  prove <secret>               - Generate time-bound proof")
        print("  session-token <secret> <uid> - Generate session token")
        print("  verify <public> '<proof>'    - Verify proof")
        return

    cmd = sys.argv[1]
    if cmd == "keygen":
        cmd_keygen()
    elif cmd == "derive":
        cmd_derive()
    elif cmd == "prove":
        cmd_prove()
    elif cmd == "session-token":
        cmd_session_token()
    elif cmd == "verify":
        cmd_verify()
    else:
        print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    main()