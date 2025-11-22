# Terces

FIDO2 hardware key symetric manager. Interfaces directly with `CTAP2` protocol in Python.

Encrypts/Decrypts secrets using your security key's `hmac-secret` extension `AES-256-GCM`.

In case your distro doesn't package directly:

- [KEKeys/](./KEKeys/README.md) - Setup helpers for `pam-u2f` to build from source latest version. 

> Helps you integrate with system even if not packaged by your distro, if it is:

`sudo pacman -S pam-u2f`

## Usage 🤫

> Global mappings require sudo. Per-user mappings **DO NOT.**
> Find mapping path in `terces.cfg`

```bash
./terces setup      # Generate mappings file
./terces unlock     # Test auth
./terces encrypt    # Store secret (prompts: name, secret, optional description)
./terces decrypt    # Retrieve secret (prompts: name)
./terces reset      # Deletes all locally stored keys
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

---

### Portable installs

For use across multiple machines, set a fixed `rp_id` in `terces.cfg` **before** setup:

```bash
# Generate unique rp_id
python3 -c "import uuid; print(f'pam://{str(uuid.uuid4())[:8]}')"
```

```json
{"mappings_file": "/etc/u2f_mappings", "rp_id": "pam://a1b2c3d4"}
```

Then:
```bash
sudo ./terces setup           # Registers key with your rp_id
./terces portable export      # Encrypts mappings file
# Copy whole TERCES folder to USB

# On new machine:
./terces portable import | sudo tee /etc/u2f_mappings
./terces unlock               # Works - same rp_id, same key
```

## Already setup on one machine

>In case you have already set it up on machine using default config:

You can still just export/import the original file which contains `rp_id`:
```bash
./terces portable export

# Copy TERCES folder to new PC, then:
./terces portable import | sudo tee /etc/u2f_mappings
./terces unlock  # verify it works
```
