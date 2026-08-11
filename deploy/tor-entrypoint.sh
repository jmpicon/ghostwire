#!/bin/sh
# Named volumes arrive root-owned. tor refuses to start unless its data
# directory is 0700 and owned by the user it runs as, so fix that here and
# drop privileges before exec'ing.
set -e

mkdir -p /var/lib/tor/ghostwire
chown -R tor:tor /var/lib/tor
chmod 0700 /var/lib/tor /var/lib/tor/ghostwire

exec su-exec tor tor -f /etc/tor/torrc
