#!/bin/sh
# Title: Loki
# Description: LAN Orchestrated Key Infiltrator  Autonomous Network Recon Payload
# Author: brAinphreAk
# Version: 1.0
# Category: Reconnaissance
# Library: libpagerctl.so (pagerctl)
#
# Pagerctl-native launcher. Invoked by pagerctl_home when it detects
# this file next to payload.sh. pagerctl_home has already torn down
# the pager and will rebuild it on return, so we skip the duckyscript
# API, the pineapplepager service, and the splash/prompt flow.

PAYLOAD_DIR="/root/payloads/user/reconnaissance/loki"
DATA_DIR="$PAYLOAD_DIR/data"

cd "$PAYLOAD_DIR" || exit 1

export PATH="/mmc/usr/bin:$PAYLOAD_DIR/bin:$PATH"
export PYTHONPATH="$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$PAYLOAD_DIR/lib:$LD_LIBRARY_PATH"
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1

if [ -d "$PAYLOAD_DIR/share/nmap/scripts" ]; then
    export NMAPDIR="$PAYLOAD_DIR/share/nmap"
elif [ -d "/mmc/usr/share/nmap/scripts" ]; then
    export NMAPDIR="/mmc/usr/share/nmap"
else
    export NMAPDIR="/usr/share/nmap"
fi

command -v python3 >/dev/null 2>&1 || exit 1

mkdir -p "$DATA_DIR" 2>/dev/null

NEXT_PAYLOAD_FILE="$DATA_DIR/.next_payload"

while true; do
    cd "$PAYLOAD_DIR"
    python3 loki_menu.py
    EXIT_CODE=$?

    if [ "$EXIT_CODE" -eq 42 ] && [ -f "$NEXT_PAYLOAD_FILE" ]; then
        NEXT_SCRIPT=$(cat "$NEXT_PAYLOAD_FILE")
        rm -f "$NEXT_PAYLOAD_FILE"
        if [ -f "$NEXT_SCRIPT" ]; then
            sh "$NEXT_SCRIPT"
            [ $? -eq 42 ] && continue
        fi
    fi

    [ "$EXIT_CODE" -eq 99 ] && continue

    break
done

exit 0
