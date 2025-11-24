# KEKeys - FIDO2 on Open-rc/Other init systems

`KEKeys` is a guide for FIDO2 on Open-rc/Other init systems. Thought it was sad to see most of documentation for Fido2 being only on systemd distros. So I just stole a bit from Gentoo wiki and played around to find what works and doesn't through `pam.d`.

- Probably the coolest 20-50$ gadget there is (next to a good USB-C Nvme adapter).

This still unfortunatly doesn't provide as strong inegration as `systemd-cryptenroll` (for [FDE](https://en.wikipedia.org/wiki/Disk_encryption#Full_disk_encryption) unlock) but perhaps we can change that.

---

Script in repo builds `pam-u2f` from source, generates **system-wide** mappings, see inside script comments for `pam.d` configuration. 

## See 

- [Setup](./setup_u2f_key) 
- [Dependancies](./build_deps)

>[!NOTE]
> This is for systems that do not package `pam-u2f` directly. And builds necessary `.so` files in the expected directory.

This script helps setup on Arch based distro but packages can be adapted for any by changing pkg man definitions.

Inside the setup script you will find all instructions needed to integrate fully to your system for it to unlock **sudo, login screen, and display manager**. 