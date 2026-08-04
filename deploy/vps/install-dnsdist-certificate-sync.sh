#!/bin/sh
set -eu

install -d -o 953 -g 953 -m 0750 /opt/hip/shared/dnsdist-tls
install -o root -g root -m 0644 \
    deploy/vps/systemd/hip-dnsdist-certificate-sync.service \
    /etc/systemd/system/hip-dnsdist-certificate-sync.service
install -o root -g root -m 0644 \
    deploy/vps/systemd/hip-dnsdist-certificate-sync.timer \
    /etc/systemd/system/hip-dnsdist-certificate-sync.timer
systemctl daemon-reload
systemctl enable --now hip-dnsdist-certificate-sync.timer
