# KEKeys - FIDO2 on Open-rc/Other init systems

`KEKeys` is a guide for FIDO2 on Open-rc/Other init systems. Thought it was sad to see most of documentation for Fido2 being only on systemd distros. So I just stole a bit from Gentoo wiki and played around to find what works and doesn't through `pam.d`.

This still unfortunatly doesn't provide as strong inegration as `systemd-cryptenroll` (for FDE unlock) but perhaps we can change that.

---

Script in repo builds `pam-u2f` from source, generates **system-wide** mappings, see inside script comments for `pam.d` configuration.

[Dependancies](./build_deps) and [Setup](./setup_u2f_key)

>[!NOTE]
> This is for systems that do not package `pam-u2f` directly. And builds necessary `.so` files in the expected directory.

This script helps setup on Arch based distro but packages can be adapted for any by changing pkg man definitions.