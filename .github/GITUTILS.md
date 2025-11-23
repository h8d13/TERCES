# Git SSH-FIDO2

## Agent PIDs

- `eval "$(ssh-agent -s)"`
- `ssh-add ~/.ssh/id_keyname_sk` or using keychain package: `eval $(keychain --eval --quiet id_keyname_sk)`

Also useful: 

- `ssh -vT git@github.com 2>&1 | grep "Offering"`
- `git remote -v`

> Check you are in ssh and not https
