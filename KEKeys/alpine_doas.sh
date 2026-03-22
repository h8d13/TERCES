#!/bin/sh
apk add bison make gcc musl-dev
git clone https://github.com/Duncaen/OpenDoas.git 
cd OpenDoas
make && make install

sed -i 's/^# permit persist :wheel/permit persist :wheel/' /etc/doas.conf

# install example /doas.pam to /etc/pam.d/doas
