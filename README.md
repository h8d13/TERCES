# Terces

<img align="left" src="./.github/assets/usb_d.svg#gh-light-mode-only" width="80" alt="usb lock icon">
<img align="left" src="./.github/assets/usb_l.svg#gh-dark-mode-only" width="80" alt="usb lock icon">

FIDO2 Hardware Security Module symetric key manager. Interfaces directly with `CTAP2` protocol **locally** in Python. Using your security key's `hmac-secret` extension using `AES-256-GCM`. More can be extended using `python-cryptography` or others. Limit to PIN is 63 chars UTF-8. 

<br clear="left">

Works for *any* Fido2 compliant USB hardware: **YubiKey** (Yubico), **Titan** (Google), **SoloKey** (US based open-source), **Nitrokey** (German leader in HSM), ...

In case your distro doesn't package directly:

- [KEKeys/](./KEKeys/README.md) - Setup helpers for `pam-u2f` to build from source latest version for any init system.
- And integrate to `pam.d` for system-login, login-manager, etc... 

Helps you blend HSM with software even if not packaged by your distro, if it is:

Set-up on arch (which asumes `base-devel git tar openssl`): 

`sudo pacman -S pam-u2f libfido2 python-fido2 python-cryptography`

---

## FIDO2 Hardware:

```bash
./terces list           # List devices
./terces info <term>    # Example "algo", empty for full info
./terces help           # Show all commands

```

## Usage 🤫

> Global mappings require sudo. Per-user mappings **DO NOT.**

```bash
./terces setup              # Generate mappings file
./terces test <type> <size> # Test files using openssl sha256sum and terces 
./terces unlock             # Test auth
./terces encrypt            # Store secret (prompts: name, secret, optional description)
./terces decrypt            # Retrieve secret (prompts: name)
./terces gen [len] [name]   # Generate password (optional: length, store as name)
./terces vault              # List stored secrets
./terces delete <name>      # Delete a secret
./terces reset              # Deletes all locally stored keys
```

```bash 
┌──[04:56]─[systemuser_$@hostx]─[~/somewhere]─[04:56]─[git:master]
└──╼ $ echo "##Terces Demo##"
##Terces Demo##
$ cat example.secret | sudo ./terces encrypt api-key "importantkey"
$ sudo ./terces decrypt api-key | xclip -sel clip
$ sk-abcdefghijklmnopqrstuvwxyz1234567890
``` 
Pipe frienly ! Again sudo would not be required if using **per-user** mappings.

>[!TIP]
> Set a strong PIN on your key but do make sure it's still relatively easy for you to enter, since 8 attempts is the default full lock-out value.
> Setup terces for local usage since the integration with browsers is already pretty neat, wanted to have a way to achieve the same **for local secrets.**

See again [KEKeys/](./KEKeys/README.md) if you want to compile from scratch and understand a bit more in depth.

>[!IMPORTANT]
> If you're wanting to use Terces and already have registered keys please see multi-hosts installs [Portable](.github/PORTABLE.md) 
> Do not run setup again as you can keep your exisitng mappings if needed. 

**Names are for you to remember.** A keys retrieved using it's name which is **never actually stored.**

## Updates

*Disclaimer:* The project will not be built as a backwards compatible one, we expect the user to **not update** if they are keeping important data.
Security is being pro-active and finding edge-cases, so building each piece of code with backwards compat would be both a risk and impossible to maintain. 

You can use:
```bash
./terces version   # Check for remote hash
./terces update    # Clones fresh copy to different folder
```
Then re-enroll manually to upgrade/migrate. For this purpose keys are stored as a clear convention inside dir `.d/terces-0003`

---

## Advanced Use Cases

<details>
<summary><b>Extras 🎁</b></summary>

### FIDO2-backed SSH Keys

Generate SSH keys backed by your security key. Requires terces auth before key generation.

```bash
./terces ssh <name>            # Generate resident ed25519-sk key or --no-res
# Set it up with respective provider
./terces ssh test gitlab.com   # Test directly (with your provider)
```
Can find more info [GITUTILS](./.github/GITUTILS.md)

Keys are saved to `~/.ssh/id_<name>_sk` and public key is stored in terces vault as `sshX:<name>`. Can then be retrieved through `decrypt` function.

**Note:** Uses OpenSSH's native FIDO2 support. Your key must support the `eddsa` algorithm.

### File/Folder Encryption

Encrypt/decrypt files or folders using FIDO2 hmac-secret derived keys. **Works from root dir where terces lives**

**Delete files** - After encryption, originals remain. Remove them yourself **when ready.**

```bash
./terces file enc /path/to/file       # Creates file.trcs or folder.tar.trcs
./terces file dec /path/to/file.trcs  # Restores original
```

**Important:** Key is derived from `key_handle + filename` — renaming `.trcs` files breaks decryption. This also strips old metadata; only `ciphertext` + `nonce` and new file details remain.

### Sharing (Asymmetric)

```bash
./terces keypub                       # Export your public key
./terces keypub <label>               # Different keypair per label
./terces share <file> <pubkey>        # Encrypt for recipient
./terces unshare <file.shrd>          # Decrypt with your FIDO2
./terces unshare <file.shrd> <label>  # Decrypt with labeled keypair
```
</details>

## Blazing fast

<details>
<summary><b>Benchmarks ᯓ🏃🏻‍♀️‍➡️</b></summary>

## Table examples

Sequential streaming on newer Dell enterprise laptop (NVMe M.2 SSD):

| Operation | File Size | Time | Speed |
|-----------|-----------|------|-------|
| **Symmetric Enc** | 10 GiB | 18.0s | 569 MB/s |
| **Symmetric Dec** | 10 GiB | 18.9s | 540 MB/s |
| **Symmetric Dec** | 2 GiB | 1.6s | 1295 MB/s |
| **Asymmetric Share** | 2 GiB | 1.9s | 1097 MB/s |
| **Asymmetric Unshare** | 2 GiB | 1.6s | 1297 MB/s |

### Run your own

Smaller files are faster due to reduced I/O overhead and better cache utilization in `/tmp`.

Run your own benchmarks:
```bash
./terces test <type> <size> # Test files using openssl sha256sum and terces 
./terces test large 2048 
# or asym instead of large
```

</details>

## Installing

- Use the `terces.cfg` file to configure to liking or control multiple FIDO2 devices.

- Running from Python in isolated venv

We have a helper script `zpya` that downloads Python deps from pip in `.venv`

- Installing *somewhere*

You can place `TERCES/` anywhere on the system or removable media

Then create a symlink either:

`ln -s /path/to/TERCES/terces ~/.local/bin/terces` or any other `bin/terces` location.

Or `alias terces='/path/to/TERCES/terces'` To use only in shell env. 

---