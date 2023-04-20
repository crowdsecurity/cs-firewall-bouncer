#!/bin/sh

set -eu

. ./scripts/_bouncer.sh

assert_root

# --------------------------------- #

systemctl stop "$SERVICE"

if ! upgrade_bin; then
    msg err "failed to upgrade $BOUNCER"
    exit 1
fi

systemctl start "$SERVICE" || msg warn "$SERVICE failed to start, please check the systemd logs"

msg succ "$BOUNCER upgraded successfully."
exit 0
