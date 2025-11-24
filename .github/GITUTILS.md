# Git-SSH-FIDO2-GPG

## Agent PIDs

- `eval "$(ssh-agent -s)"`
- `ssh-add ~/.ssh/id_keyname_sk` or using keychain package: `eval $(keychain --eval --quiet id_keyname_sk)`

Again I have this as an alias or even in my open VSCodium command^^

Also useful: 

- `ssh -vT git@yourprovider.com 2>&1 | grep "Offering"`
- `git remote -v`

> Check you are in ssh and not https

## Signign commits using GPG

- `gpg --full-generate-key`

## Walk through steps

`gpg --list-keys --keyid-format-long`
`gpg --armor --export KEY_ID`
`git config --global user.signingkey KEY_ID` 
`git config --global commit.gpgsign true`

