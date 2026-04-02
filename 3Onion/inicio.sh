#!/bin/sh
set -e

# Tengo que crear un directorio para sshd porque sino no arranca dentro de run.
mkdir -p /run/sshd
chmod 755 /run/sshd 

/usr/bin/tor -f /etc/tor/torrc & 

/usr/sbin/sshd -D -e -f /etc/ssh/sshd_config &
# -D : No daemonizar, se queda en primer plano
# -e : Enviar los logs a stderr
# -f : Especificar un archivo de configuración

exec nginx -g 'daemon off;'