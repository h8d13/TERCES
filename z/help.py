# help.py - Show available commands
print("""TERCES - FIDO2 Hardware Security Module

Device:
  list                    List FIDO2 devices
  info [term]             Device info (filter by term)

Secrets:
  setup                   Generate mappings file
  unlock                  Test authentication
  encrypt                 Store a secret (or: stdin | encrypt <name> [desc])
  decrypt                 Retrieve a secret
  gen [len] [name]        Generate password (default 24, optional store)
  vault                   List stored secrets
  delete <name>           Delete a secret
  reset                   Delete all data

Files:
  file enc <path>         Encrypt file/folder (.trcs)
  file dec <path>         Decrypt file/folder

SSH:
  ssh <name>              Generate FIDO2-backed SSH key
  ssh test <host>         Test SSH key offering

Sharing:
  keypub [label]          Export public key
  share <file> <pub>      Encrypt for recipient (.shrd)
  unshare <file> [label]  Decrypt shared file

Other:
  portable export|import  Backup/restore mappings
  version                 Check for updates
  update                  Download latest version
  help                    This help
""")
