#!/bin/sh

for DIR in /var/run/named /var/dump /var/stats /var/log/named /usr/local/etc/namedb/primary /usr/local/etc/namedb/keys; do
	mkdir -p ${DIR}
	chown -R bind:bind ${DIR}
	chmod 755 ${DIR}
done
