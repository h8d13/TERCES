# Terces

FIDO2 hardware key symetric manager. Interfaces directly with `CTAP2` protocol in Python.

Encrypts/Decrypts secrets using your security key's `hmac-secret` extension `AES-256-GCM`.

- [KEKeys/](./KEKeys/README.md) - Setup helpers for `pam-u2f` to build from source latest version. 

> Helps you integrate with system + generate initial mappings.

## Usage 🤫

> Global mappings require sudo. Per-user mappings **DO NOT.**
> Find mapping path in `terces.cfg`

```bash
./terces setup      # Generate mappings file
./terces unlock     # Test auth
./terces encrypt    # Store secret (prompts: name, secret, optional description)
./terces decrypt    # Retrieve secret (prompts: name)
./terces reset      # Deletes all locally stored keys
./terces portable   # Usage on portable (import/export) Set rp_id in config or same hostnames
```

>[!TIP]
> Set a strong PIN on your key but do make sure it's still relatively easy for you to enter, since 8 attempts is the default full lock-out value.
> Setup this project for local usage since the integration with browsers is already pretty neat, I wanted to have a way to achieve the same for local secrets.

---

*Disclaimer:* The project will not be built as a backwards compatible one, we expect the user to **not update** if they are keeping important data.
Security is being pro-active and finding edge-cases, so building each piece of code with backwards compat would be both a risk and impossible to maintain. 

You can use:
```bash
./terces version   # Check for remote hash
./terces update    # Clones fresh copy to different folder
```
Then re-enroll manually to upgrade/migrate.