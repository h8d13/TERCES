# Terces

FIDO2 hardware key symetric manager. 
Encrypts secrets using your security key's `hmac-secret` extension `AES-256-GCM`.

## Usage

```bash
./terces unlock    # Test auth
./terces encrypt   # Store secret (prompts: name, secret, optional description)
./terces decrypt   # Retrieve secret (prompts: name)
```

- [KEKeys/](./KEKeys/README.md) - Setup helpers for `pam-u2f` on non-systemd systems
