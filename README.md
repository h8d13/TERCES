# Terces

FIDO2 hardware key symetric manager. Interfaces directly with `CTAP2` protocol in Python.

Encrypts/Decrypts secrets using your security key's `hmac-secret` extension `AES-256-GCM`.

- [KEKeys/](./KEKeys/README.md) - Setup helpers for `pam-u2f` to build from source latest version.

## Usage

```bash
./terces version   # Check for remote hash
./terces unlock    # Test auth
./terces encrypt   # Store secret (prompts: name, secret, optional description)
./terces decrypt   # Retrieve secret (prompts: name)
./terces reset     # Deletes all stored keys
```

>[!TIP]
> Set a strong PIN on your key but do make sure it's still relatively easy for you to enter, since 8 attempts is the default full lock-out value.
> Setup this project for local usage since the integration with browsers is already pretty neat, I wanted to have a way to achieve the same for local secrets.