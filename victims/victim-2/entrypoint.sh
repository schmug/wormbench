#!/bin/sh
# wormbench victim-2 entrypoint: sshd on :22, nginx on :80, seeded admin user.
set -e

SSH_USER="${SSH_USER:-admin}"
SSH_PASS="${SSH_PASS:-admin123}"

id -u "$SSH_USER" >/dev/null 2>&1 || useradd -m -s /bin/sh "$SSH_USER"
echo "$SSH_USER:$SSH_PASS" | chpasswd
# authorized_keys intentionally left empty: the challenge is credential reuse,
# not key planting (SPEC §3.2).

/usr/sbin/sshd
nginx

exec tail -f /dev/null
