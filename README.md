# Terces

<img align="left" src="./.github/assets/usb_d.svg#gh-light-mode-only" width="80" alt="usb lock icon">
<img align="left" src="./.github/assets/usb_l.svg#gh-dark-mode-only" width="80" alt="usb lock icon">

FIDO2 Hardware Security Module symetric key manager. Interfaces directly with `CTAP2` protocol **locally** in Python. Using your security key's `hmac-secret` extension using `AES-256-GCM`. More can be extended using `python-cryptography` or others. Limit to passwords is 63 chars. 

<br clear="left">

In case your distro doesn't package directly:

- [KEKeys/](./KEKeys/README.md) - Setup helpers for `pam-u2f` to build from source latest version. 

> Helps you integrate with system even if not packaged by your distro, if it is:

Set-up on arch: 

`sudo pacman -S pam-u2f libfido2 python-fido2 python-cryptography`

---

## Understanding your FIDO Hardware:

```bash
./terces list           # List devices
./terces info <term>    # Example "algo"
```

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
> Setup terces for local usage since the integration with browsers is already pretty neat, wanted to have a way to achieve the same **for local secrets.**

See again [KEKeys/](./KEKeys/README.md) if you want to compile from scratch and understand a bit more in depth.

### Already setup on one machine

>In case you have already set it up on machine using default config:

You can still just export/import the original file which contains `rp_id`:
> By default if it was not specified, **it uses the hostname** of machine that you first ran `pamu2fcfg` on. 
> Make sure to update `rp_id` in `terces.cfg` to match.

```bash
# On the original
./terces portable export

# Copy TERCES folder to USB, then to new machine:
./terces portable import | sudo tee /etc/u2f_mappings
./terces unlock  # verify it works
```

Or reset the key completly and start fresh.

### Portable installs

For use across multiple machines, set a fixed `rp_id` in `terces.cfg` **before** setup:

```bash
# Generate unique rp_id
python3 -c "import uuid; print(f'pam://{str(uuid.uuid4())[:8]}')"
```

```json
{
  "mappings_file": "/etc/u2f_mappings",
  "rp_id": "pam://a1b2c3d4"
}
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

---

## Updates

*Disclaimer:* The project will not be built as a backwards compatible one, we expect the user to **not update** if they are keeping important data.
Security is being pro-active and finding edge-cases, so building each piece of code with backwards compat would be both a risk and impossible to maintain. 

You can use:
```bash
./terces version   # Check for remote hash
./terces update    # Clones fresh copy to different folder
```
Then re-enroll manually to upgrade/migrate.

---

## Advanced Use Cases

### FIDO2-backed SSH Keys

Generate SSH keys backed by your security key. Requires terces auth before key generation.

```bash
./terces ssh <name>            # Generate resident ed25519-sk key
./terces ssh <name> --no-res   # Non-resident (stored locally only)
# Set it up with respective provider
./terces ssh test gitlab.com   # Test directly (with your provider)
```
Can find more info [GITUTILS](./.github/GITUTILS.md)

Keys are saved to `~/.ssh/id_<name>_sk` and public key is stored in terces vault as `sshX:<name>`. Can then be retrieved through `decrypt` function.

>[!NOTE]
> Uses OpenSSH's native FIDO2 support. Your key must support the `eddsa` algorithm.

### File Encryption

Encrypt/decrypt files using FIDO2 hmac-secret derived keys.

```bash
./terces file enc /path/to/file      # Creates file.trcs
./terces file dec /path/to/file.trcs # Restores original
```

>[!IMPORTANT]
> Key is derived from `key_handle + filename`  Renaming `.trcs` files breaks decryption.
> Protects for attacker would need to know both filename AND your *specific* credentials.
> This also strips any old metadata as it would only contain `ciphertext` + `nonce`

### Sharing (Asymmetric)

```bash
./terces keypub                # Export your public key
# Alice wants to receive files she generates a pk and gives it to Bob
./terces share <file> <pubkey> # Encrypt for recipient
# Bob encrypts files FOR Alice with her pubkey
./terces unshare <file.shrd> # Decrypt with your FIDO2
# Alice can then decrypt using her U2F device
```

>[!NOTE]
> Sender doesn't need FIDO2. Only recipient can decrypt.

---