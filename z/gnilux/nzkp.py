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
    def from_int(cls, n, with_checksum=False):
        if n == 0:
            trits = [0]
        else:
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

        if with_checksum:
            checksum_value = sum(trits) % 3
            # Map {0, 1, 2} → {0, 1, -1} (valid trit space)
            checksum_trit = [0, 1, -1][checksum_value]
            trits.append(checksum_trit)

        return cls(trits)

    @classmethod
    def from_packed(cls, packed_str):
        """Decode from packed base64 format"""
        import base64
        data = base64.urlsafe_b64decode(packed_str.encode('ascii'))

        # Read trit count from first 2 bytes
        trit_count = (data[0] << 8) | data[1]
        trits = []

        # Unpack 5 trits per byte
        for byte in data[2:]:
            value = byte
            for _ in range(5):
                trit_shifted = value % 3
                trit = trit_shifted - 1
                trits.append(trit)
                value //= 3

        return cls(trits[:trit_count])

    def to_int(self, verify_checksum=False):
        if verify_checksum:
            if len(self.trits) < 2:
                raise ValueError("No checksum present")

            data_trits = self.trits[:-1]
            claimed_checksum = self.trits[-1]
            checksum_value = sum(data_trits) % 3
            # Map {0, 1, 2} → {0, 1, -1}
            expected_checksum = [0, 1, -1][checksum_value]

            if claimed_checksum != expected_checksum:
                raise ValueError("Checksum verification failed")

            # Convert without checksum trit
            result = 0
            for i, trit in enumerate(data_trits):
                result += trit * (3 ** i)
            return result
        else:
            result = 0
            for i, trit in enumerate(self.trits):
                result += trit * (3 ** i)
            return result

    def to_packed(self):
        """Encode to packed base64 format (5 trits per byte)"""
        import base64

        # Store trit count in first 2 bytes
        trit_count = len(self.trits)
        bytes_data = [trit_count >> 8, trit_count & 0xFF]

        # Pack 5 trits per byte
        for i in range(0, len(self.trits), 5):
            chunk = self.trits[i:i+5]
            value = 0
            for j, trit in enumerate(chunk):
                value += (trit + 1) * (3 ** j)
            bytes_data.append(value)

        return base64.urlsafe_b64encode(bytes(bytes_data)).decode('ascii')

    def __str__(self):
        """Human-readable format"""
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
    
    def issue_session_token(self, verified_proof, user_id, nonce=None, max_uses=None):
        """
        Server-side: Issue a session token after verifying a client proof.

        Args:
            verified_proof: Already-verified proof dict from client
            user_id: User identifier
            nonce: Optional nonce (auto-generated if None)
            max_uses: Optional max verification count (None = unlimited)

        Returns:
            Dict with token and session data to store
        """
        if nonce is None:
            nonce = secrets.token_hex(16)

        # Generate token from proof + session data
        combined = f"{verified_proof['commitment']}{verified_proof['challenge']}{user_id}{nonce}{verified_proof['timestamp']}"
        hash_val = hashlib.sha512(combined.encode()).hexdigest()
        hash_int = int(hash_val, 16)

        # 80 trits for data + 1 checksum trit = 81 total
        token_int = hash_int % (3 ** 80)
        token_id = TZKP.from_int(token_int, with_checksum=True)

        session_data = {
            "token": token_id.to_packed(),
            "proof": verified_proof,
            "nonce": nonce,
            "user_id": user_id
        }

        if max_uses is not None:
            session_data["max_uses"] = max_uses
            session_data["use_count"] = 0

        return session_data
    
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

    def verify_session_token(self, public_key, token_str, stored_proof, stored_nonce, stored_user_id, use_count=None, max_uses=None):
        """
        Verify a session token against stored session data.
        Client sends only the token, server looks up stored session data.

        Args:
            public_key: The public key to verify against
            token_str: The trit-encoded token string from client
            stored_proof: The proof dict stored server-side when session was created
            stored_nonce: The nonce stored server-side
            stored_user_id: The user_id stored server-side
            use_count: Current use count (optional, for rate limiting)
            max_uses: Maximum allowed uses (optional)

        Returns:
            (bool, str): (valid, message)
        """
        # Check use count limit
        if max_uses is not None and use_count is not None:
            if use_count >= max_uses:
                return False, f"Token use limit exceeded ({use_count}/{max_uses})"

        # First verify the stored ZKP proof
        proof_valid, proof_msg = self.verify_proof(public_key, stored_proof)
        if not proof_valid:
            return False, f"Stored proof invalid: {proof_msg}"

        # Reconstruct the expected token from stored session data
        combined = f"{stored_proof['commitment']}{stored_proof['challenge']}{stored_user_id}{stored_nonce}{stored_proof['timestamp']}"
        hash_val = hashlib.sha512(combined.encode()).hexdigest()
        hash_int = int(hash_val, 16)
        expected_token_int = hash_int % (3 ** 80)

        # Decode and verify client's packed token
        try:
            token_tzkp = TZKP.from_packed(token_str)
            actual_token_int = token_tzkp.to_int(verify_checksum=True)
        except ValueError as e:
            return False, f"Token validation failed: {e}"
        except Exception as e:
            return False, f"Failed to decode token: {e}"

        # Verify client token matches expected value
        if actual_token_int == expected_token_int:
            return True, "Valid session token"
        else:
            return False, "Token mismatch - invalid or tampered"
