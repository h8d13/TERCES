#!/usr/bin/env python3
import sys
import json
import hashlib
import secrets
import time

class BalancedTernary:
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

class ProductionTritZKP:
    def __init__(self):
        # Safe prime group (RFC 3526 - 2048-bit MODP Group)
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
        
        # Generator
        self.g = 2
        
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
        secret_trits = BalancedTernary.from_int(secret_mod)
        public_key = pow(self.g, secret_mod, self.p)
        public_trits = BalancedTernary.from_int(public_key % 6561)  # Keep trit display manageable
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
        
        commit_trits = BalancedTernary.from_int(commitment % 6561)
        
        return {
            "commit_trits": str(commit_trits),
            "commitment": str(commitment),
            "challenge": str(challenge),
            "response": str(response),
            "timestamp": timestamp
        }
    
    def generate_trit_cookie(self, secret, user_salt, ip_hash, session_nonce):
        # Generate ZKP proof
        proof = self.prove_knowledge(secret)
        
        # Combine proof components with user-specific data + IP binding + session nonce
        # This makes it non-deterministic and IP-bound
        combined_data = f"{proof['commitment']}{proof['challenge']}{user_salt}{ip_hash}{session_nonce}{proof['timestamp']}"
        
        # Create cryptographically secure hash
        hash_val = hashlib.sha512(combined_data.encode()).hexdigest()
        
        # Convert hash to integer then to balanced ternary
        hash_int = int(hash_val, 16)
        
        # Reduce to manageable trit size while maintaining entropy
        reduced_int = hash_int % (3 ** 81)  # 81 trits = ~128 bits entropy
        
        trit_cookie = BalancedTernary.from_int(reduced_int)
        
        return {
            "trit_cookie": str(trit_cookie),
            "proof": proof,
            "session_nonce": session_nonce,
            "ip_hash": ip_hash
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
        print("Usage: zkp_cli.py keygen <secret_number>")
        return
    
    secret = int(sys.argv[2])
    zkp = ProductionTritZKP()
    secret_trits, public_trits, public_key = zkp.generate_keypair(secret)
    
    print(f"Secret: {secret} -> {secret_trits}")
    print(f"Public (trit): {public_trits}")
    print(f"Public (full): {public_key}")

def cmd_prove():
    if len(sys.argv) < 3:
        print("Usage: zkp_cli.py prove <secret_number>")
        return
    
    secret = int(sys.argv[2])
    zkp = ProductionTritZKP()
    
    proof = zkp.prove_knowledge(secret)
    print(json.dumps(proof, indent=2))

def cmd_trit_cookie():
    if len(sys.argv) < 6:
        print("Usage: zkp_cli.py trit-cookie <secret_number> <user_salt> <ip_hash> <session_nonce>")
        return
    
    secret = int(sys.argv[2])
    user_salt = sys.argv[3]
    ip_hash = sys.argv[4]
    session_nonce = sys.argv[5]
    zkp = ProductionTritZKP()
    
    result = zkp.generate_trit_cookie(secret, user_salt, ip_hash, session_nonce)
    print(json.dumps(result, indent=2))

def cmd_verify():
    if len(sys.argv) < 4:
        print("Usage: zkp_cli.py verify <public_key> <proof_json>")
        return
    
    public_key = int(sys.argv[2])
    proof_json = sys.argv[3]
    
    zkp = ProductionTritZKP()
    proof_data = json.loads(proof_json)
    
    valid, message = zkp.verify_proof(public_key, proof_data)
    print(f"{'VALID' if valid else 'INVALID'}: {message}")

def main():
    if len(sys.argv) < 2:
        print("Production Balanced Ternary ZKP CLI")
        print("Commands:")
        print("  keygen <secret>     - Generate keypair")
        print("  prove <secret>      - Generate time-bound proof")
        print("  trit-cookie <secret> <salt> <ip> <nonce> - Generate trit cookie")
        print("  verify <public> '<proof_json>' - Verify proof")
        return
    
    cmd = sys.argv[1]
    if cmd == "keygen":
        cmd_keygen()
    elif cmd == "prove":
        cmd_prove()
    elif cmd == "trit-cookie":
        cmd_trit_cookie()
    elif cmd == "verify":
        cmd_verify()
    else:
        print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    main()