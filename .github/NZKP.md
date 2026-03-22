# N-ZKP - Time-Bound Zero-Knowledge Proofs

> **What it provides:** Time-bound authentication with entropy-checked secrets backed by FIDO2 hardware but exportable outside of FIDO usage.

Previously terces had no way to:
- Generate time-limited credentials that expire automatically
- Verify identity without physical FIDO2 key access
- Check entropy of derived secrets
- Prove knowledge without revealing the secret

N-ZKP solves this using Schnorr proofs + scrypt + FIDO2 hmac-secret.

---

## Basic Workflow

```
┌──────────────────────────────────────────────────────────┐
│ SETUP (once per device)                                  │
├──────────────────────────────────────────────────────────┤
│ $ terces zkp init 2048                                   │
│   • Derives secret from FIDO2 (touch)                    │
│   • Runs scrypt hardening                                │
│   • Checks entropy (≥64 bits required)                   │
│   • Stores keypair in encrypted vault                    │
│                                                           │
│ $ terces zkp export > pubkey.json                        │
│   • Decrypts vault (touch)                               │
│   • Exports public key for sharing                       │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│ LOCAL VERIFICATION (with FIDO2 + vault)                  │
├──────────────────────────────────────────────────────────┤
│ $ terces zkp prove 300                                   │
│   • Decrypt keypair from vault (touch)                   │
│   • Re-derive secret from FIDO2 (touch)                  │
│   • Generate 5-minute proof                              │
│                                                           │
│ $ terces zkp verify '<proof>'                            │
│   • Load pubkey from vault (touch)                       │
│   • Verify Schnorr equation                              │
│   • Check timestamp expiry                               │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│ REMOTE VERIFICATION (no FIDO2, offline)                  │
├──────────────────────────────────────────────────────────┤
│ $ terces zkp prove 60 > proof.json                       │
│   • Generate proof on local machine (touch)              │
│                                                          │
│ # On remote server (no FIDO2 needed):                    │

$ terces zkp verify-remote "$(cat proof.json)" "$(cat pubkey.json)" 

│   • Pure math verification                               │
│   • No vault access needed                               │
│   • No secrets required                                  │
└──────────────────────────────────────────────────────────┘
```

---

## Command Details

### `terces zkp init [bits]`
Initialize ZKP keypair derived from FIDO2.

```bash
terces zkp init           # Default 2048-bit
terces zkp init 3072      # Stronger 3072-bit
terces zkp init 4096      # Strongest 4096-bit
```
**Security:** Private key never leaves FIDO2 device, derived on-demand.

---

### `terces zkp info`
Show stored keypair information.

```bash
terces zkp info
```

**Process:**
1. Decrypts vault entry `zkp:keypair` (requires touch)
2. Displays bits, salt, and public key prefix

**Output:**
```
Bits: 2048
Salt: 4d4b837270268980e17b173ea6da6b2c
Public key: 2031815103414255465339173111175390638831728377...
```

**Requires:** FIDO2 key (to decrypt vault)

---

### `terces zkp prove [ttl]`
Generate time-bound proof of knowledge.

```bash
terces zkp prove           # Default 300s (5 min)
terces zkp prove 60        # 1 minute proof
terces zkp prove 3600      # 1 hour proof
```

**Output format:**
```json
{
  "commit_trits": "1T001100",
  "commitment": "208915740...",
  "challenge": "301760890...",
  "response": "149251063...",
  "timestamp": 1764002126,
  "bits": 2048,
  "ttl": 300
}
```

**Proof properties:**
- Expires after `ttl` seconds from `timestamp`
- Cannot be forged without the secret
- Cannot be replayed (timestamp uniqueness)
- Verifiable with only public key

**Requires:** FIDO2 key (2 touches: vault decrypt + secret derivation)

---

### `terces zkp verify '<proof>'`
Verify proof against stored public key.

```bash
terces zkp verify "$(cat proof.json)"
```
Returns VALID/INVALID + remaining time

**Output:**
```
[SUCCESS] VALID: Valid proof
Expires in 294s
```

**Requires:** FIDO2 key (to decrypt vault)

**Use case:** Local verification when you have vault access.

---

### `terces zkp export`
Export public key for remote verification.

```bash
terces zkp export > pubkey.json
```
**Output format:**
```json
{
  "public_key": "2031815103...",
  "bits": 2048
}
```

**Requires:** FIDO2 key (to decrypt vault)

**Use case:** Share with remote verifiers who need to check proofs without your FIDO2 key.

---

### `terces zkp verify-remote '<proof>' '<pubkey>'`
Verify proof with exported public key.

```bash
# Export your public key
terces zkp export > pubkey.json

# Generate proof
terces zkp prove 60 > proof.json

# Verify anywhere (no FIDO2, no vault needed)
terces zkp verify-remote "$(cat proof.json)" "$(cat pubkey.json)"
```

**No FIDO2 required** - pure cryptographic verification

**Output:**
```
[SUCCESS] VALID: Valid proof
```

---

## Security Properties

| Property | Value |
|----------|-------|
| **Proof lifetime** | Configurable (default 300s) |
| **Replay protection** | Timestamp in Fiat-Shamir challenge |
| **Hardware binding** | FIDO2 hmac-secret + scrypt |
| **Entropy requirement** | ≥64 bits (warns <80 bits) |
| **Cryptographic groups** | RFC 7919 FFDHE (2048/3072/4096-bit) |
| **Key derivation** | scrypt (N=2^14, r=8, p=1, dklen=32) |
| **Proof algorithm** | Schnorr non-interactive (Fiat-Shamir) |
| **Verifier requirements** | Public key only (no secrets) |

---

## Testing

```bash
# Unit tests (no FIDO2 required)
./terces test zkp 2048

# Integration tests (requires FIDO2 key)
./terces test zkp-fido 2048
```

**Test coverage:**
- RFC 7919 parameter loading (2048/3072/4096-bit)
- Entropy checking (64-bit minimum)
- Scrypt determinism (same salt → same key)
- Proof generation and verification
- Invalid proof rejection
- Session token generation

---

## See Also

- [RFC 7919 - FFDHE Groups](https://www.rfc-editor.org/rfc/rfc7919) - Standardized DH parameters
- [Schnorr Signatures](https://en.wikipedia.org/wiki/Schnorr_signature) - Digital signature scheme
- [Fiat-Shamir Heuristic](https://en.wikipedia.org/wiki/Fiat%E2%80%93Shamir_heuristic) - Non-interactive proofs
- [CTAP2 hmac-secret](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#sctn-hmac-secret-extension) - FIDO2 extension spec
- [Scrypt KDF](https://tools.ietf.org/html/rfc7914) - Password-based key derivation
