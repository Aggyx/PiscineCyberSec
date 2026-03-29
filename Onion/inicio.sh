#!/bin/sh
/usr/bin/tor -f /etc/tor/torrc & 
/usr/sbin/sshd -D &
exec nginx -g 'daemon off;'