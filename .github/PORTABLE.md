# Portable 

## Simply

```bash
cp path/to/mappings /path/to/usb/mappings
# perform the same inversly on the target
```

And make sure to configure `terces.cfg` to match rp_id field see examples 

Or we also provide some utils to customize or transport encrypted.

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