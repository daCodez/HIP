#!/bin/sh
set -eu

anchor=/var/lib/unbound/root.key
if [ ! -s "$anchor" ]; then
    unbound-anchor -a "$anchor"
fi

exec unbound -d -c /etc/unbound/unbound.conf
