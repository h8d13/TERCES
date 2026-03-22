# doas apk add openssh-sk-helper

# lets you test in a seperate tty
#doas ln -s agetty /etc/init.d/agetty.tty2
#doas rc-service agetty.tty2 start

# then create:

#/etc/pam.d/login    

#auth      sufficient   pam_u2f.so cue
#auth      include      base-auth
#account   include      base-account
#password  include      base-password
#session   include      base-session

# this also works for any pam.d like lockscreen
