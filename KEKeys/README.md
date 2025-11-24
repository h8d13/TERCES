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

---

## Memory Hardening (OpenRC)

Terces derived keys briefly exist in RAM during operations. For truly tin-foil paranoid setups:
Assumes you are already on a FDE system. 

### Compressed zram swap with zramen

```bash
# Install
sudo pacman -S zramen zramen-openrc

# Configure /etc/conf.d/zramen
size="2G"
algo="zstd"

# Enable and start
sudo rc-update add zramen default
sudo rc-service zramen start
```

### Encrypted zram (dm-crypt wrapper)

zramen doesn't encrypt, wrap manually if needed:

```bash
# After zramen creates /dev/zram0
sudo swapoff /dev/zram0
sudo cryptsetup open --type plain /dev/zram0 zram-crypt --key-file /dev/urandom
sudo mkswap /dev/mapper/zram-crypt
sudo swapon -p 100 /dev/mapper/zram-crypt
```

>[!NOTE]
> On FDE systems with no disk swap, encrypted zram is overkill - RAM is volatile and never persists.

### Disable core dumps

Add to `/etc/security/limits.conf`

```
* hard core 0
```

### Verify no disk swap

```bash
# Should only show zram, no /dev/sdX or files
cat /proc/swaps
```

>[!TIP]
> With zram + no disk swap, your derived keys never touch persistent storage even under memory pressure. 