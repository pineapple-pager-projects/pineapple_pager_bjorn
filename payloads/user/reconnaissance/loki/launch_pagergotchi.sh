#!/bin/sh
# Title: Pagergotchi
# Requires: /root/payloads/user/reconnaissance/pagergotchi

PAGERGOTCHI_DIR="/root/payloads/user/reconnaissance/pagergotchi"

# Setup paths
export PATH="/mmc/usr/bin:$PATH"
export PYTHONPATH="$PAGERGOTCHI_DIR/lib:$PAGERGOTCHI_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$PAGERGOTCHI_DIR/lib:$PAGERGOTCHI_DIR:$LD_LIBRARY_PATH"

# Ensure pineapd is stopped so we can use the display
if pgrep -x pineapple >/dev/null; then
    /etc/init.d/pineapplepager stop 2>/dev/null
    sleep 0.3
fi

cd "$PAGERGOTCHI_DIR"
python3 run_pagergotchi.py
exit $?
