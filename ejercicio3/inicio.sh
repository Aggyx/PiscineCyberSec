#!/bin/sh

service nginx start
service ssh start
tor -f /etc/tor/torrc
