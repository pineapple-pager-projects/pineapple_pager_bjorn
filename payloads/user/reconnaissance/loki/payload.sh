#!/bin/sh
# Title: Loki
# Description: Autonomous network reconnaissance companion for WiFi Pineapple Pager - Network scanning, brute force, and data exfiltration
# Author: brAinphreAk
# Version: 1.0
# Category: Reconnaissance
# Library: libpagerctl.so (pagerctl)

# Payload directory (standard Pager installation path)
PAYLOAD_DIR="/root/payloads/user/reconnaissance/loki"
DATA_DIR="$PAYLOAD_DIR/data"

cd "$PAYLOAD_DIR" || {
    LOG "red" "ERROR: $PAYLOAD_DIR not found"
    exit 1
}

#
# Find and setup pagerctl dependencies (libpagerctl.so + pagerctl.py)
# lib/ is the canonical location — check it first, then payload root, then external PAGERCTL
#
PAGERCTL_FOUND=false
for dir in "$PAYLOAD_DIR/lib" "$PAYLOAD_DIR" "/mmc/root/payloads/user/utilities/PAGERCTL"; do
    if [ -f "$dir/libpagerctl.so" ] && [ -f "$dir/pagerctl.py" ]; then
        PAGERCTL_DIR="$dir"
        PAGERCTL_FOUND=true
        break
    fi
done

if [ "$PAGERCTL_FOUND" = false ]; then
    LOG ""
    LOG "red" "=== MISSING DEPENDENCY ==="
    LOG ""
    LOG "red" "libpagerctl.so and pagerctl.py not found!"
    LOG ""
    LOG "Searched:"
    for dir in "$PAYLOAD_DIR/lib" "$PAYLOAD_DIR" "/mmc/root/payloads/user/utilities/PAGERCTL"; do
        LOG "  $dir"
    done
    LOG ""
    LOG "Install PAGERCTL payload or copy files to:"
    LOG "  $PAYLOAD_DIR/lib/"
    LOG ""
    LOG "Press any button to exit..."
    WAIT_FOR_INPUT >/dev/null 2>&1
    exit 1
fi

# Copy to lib/ if found outside of it (payload root or external PAGERCTL)
if [ "$PAGERCTL_DIR" != "$PAYLOAD_DIR/lib" ]; then
    mkdir -p "$PAYLOAD_DIR/lib" 2>/dev/null
    cp "$PAGERCTL_DIR/libpagerctl.so" "$PAYLOAD_DIR/lib/" 2>/dev/null
    cp "$PAGERCTL_DIR/pagerctl.py" "$PAYLOAD_DIR/lib/" 2>/dev/null
    LOG "green" "Copied pagerctl from $PAGERCTL_DIR to lib/"
fi

#
# Setup local paths for bundled binaries and libraries
# Uses libpagerctl.so for display/input handling
# MMC paths needed when python3 installed with opkg -d mmc
#
export PATH="/mmc/usr/bin:$PAYLOAD_DIR/bin:$PATH"
export PYTHONPATH="$PAYLOAD_DIR/lib:$PAYLOAD_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$PAYLOAD_DIR/lib:$LD_LIBRARY_PATH"
export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
# NMAPDIR: prefer bundled nmap data, fall back to mmc, then system
if [ -d "$PAYLOAD_DIR/share/nmap/scripts" ]; then
    export NMAPDIR="$PAYLOAD_DIR/share/nmap"
elif [ -d "/mmc/usr/share/nmap/scripts" ]; then
    export NMAPDIR="/mmc/usr/share/nmap"
else
    export NMAPDIR="/usr/share/nmap"
fi

#
# Check for Python3 and python3-ctypes - required system dependencies
#
NEED_PYTHON=false
NEED_CTYPES=false

if ! command -v python3 >/dev/null 2>&1; then
    NEED_PYTHON=true
    NEED_CTYPES=true
elif ! python3 -c "import ctypes" 2>/dev/null; then
    NEED_CTYPES=true
fi

if [ "$NEED_PYTHON" = true ] || [ "$NEED_CTYPES" = true ]; then
    LOG ""
    LOG "red" "=== MISSING REQUIREMENT ==="
    LOG ""
    if [ "$NEED_PYTHON" = true ]; then
        LOG "Python3 is required to run Loki."
    else
        LOG "Python3-ctypes is required to run Loki."
    fi
    LOG "All other dependencies are bundled."
    LOG ""
    LOG "green" "GREEN = Install dependencies (requires internet)"
    LOG "red" "RED   = Exit"
    LOG ""

    while true; do
        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in
            "GREEN"|"A")
                LOG ""
                LOG "Updating package lists..."
                opkg update 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                LOG ""
                LOG "Installing Python3 + dependencies to MMC..."
                opkg -d mmc install python3 python3-ctypes python3-xml python3-urllib python3-openssl python3-uuid 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                LOG ""
                # Verify installation succeeded
                if command -v python3 >/dev/null 2>&1 && python3 -c "import ctypes" 2>/dev/null; then
                    LOG "green" "Python3 installed successfully!"
                    sleep 1
                else
                    LOG "red" "Failed to install Python3"
                    LOG "red" "Check internet connection and try again."
                    LOG ""
                    LOG "Press any button to exit..."
                    WAIT_FOR_INPUT >/dev/null 2>&1
                    exit 1
                fi
                break
                ;;
            "RED"|"B")
                LOG "Exiting."
                exit 0
                ;;
        esac
    done
fi

#
# Check Loki dependencies
# Python packages are bundled in lib/, nmap-full is bundled in bin/ + share/
#
check_dependencies() {
    LOG ""
    LOG "Checking dependencies..."

    # Verify bundled nmap works
    if ! nmap --version >/dev/null 2>&1; then
        LOG ""
        LOG "red" "ERROR: nmap binary not working!"
        LOG ""
        LOG "Press any button to exit..."
        WAIT_FOR_INPUT >/dev/null 2>&1
        exit 1
    fi

    LOG "green" "All dependencies found!"
}

# ============================================================
# CLEANUP
# ============================================================

cleanup() {
    # Restart pager service if not running
    if ! pgrep -x pineapple >/dev/null; then
        /etc/init.d/pineapplepager start 2>/dev/null
    fi
}

# Ensure pager service restarts on exit
trap cleanup EXIT

# ============================================================
# MAIN
# ============================================================

# Check dependencies automatically
check_dependencies

# Check network connectivity (at least one interface with IP)
HAS_NETWORK=false
for IP in $(ip -4 addr 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1); do
    if [ "$IP" != "127.0.0.1" ]; then
        HAS_NETWORK=true
        break
    fi
done

if [ "$HAS_NETWORK" = false ]; then
    LOG ""
    LOG "red" "=== NO NETWORK CONNECTED ==="
    LOG ""
    LOG "Loki requires a network connection to scan."
    LOG "Please connect to a network first:"
    LOG "  - WiFi client mode (wlan0cli)"
    LOG "  - Ethernet/USB (br-lan)"
    LOG ""
    LOG "Press any button to exit..."
    WAIT_FOR_INPUT >/dev/null 2>&1
    exit 1
fi

# Show info/splash screen
LOG ""
LOG "green" "Loki for WiFi Pineapple Pager"
LOG "cyan" "by *brAinphreAk*"
LOG ""
LOG "yellow" "Features:"
LOG "cyan" "  - Automated network reconnaissance"
LOG "cyan" "  - Port scanning with nmap"
LOG "cyan" "  - SSH/SMB/FTP/Telnet/RDP/SQL brute force"
LOG "cyan" "  - Data exfiltration"
LOG "cyan" "  - Vulnerability scanning"
LOG "cyan" "  - Web UI and theme support"
LOG ""
LOG "green" "GREEN = Start"
LOG "red" "RED = Exit"
LOG ""

while true; do
    BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
    case "$BUTTON" in
        "GREEN"|"A")
            break
            ;;
        "RED"|"B")
            LOG "Exiting."
            exit 0
            ;;
    esac
done

# Create data directory
mkdir -p "$DATA_DIR" 2>/dev/null

# Stop pager service and show spinner while initializing
SPINNER_ID=$(START_SPINNER "Starting Loki...")
/etc/init.d/pineapplepager stop 2>/dev/null
sleep 0.5
STOP_SPINNER "$SPINNER_ID" 2>/dev/null

# Payload loop — Loki can hand off to other apps via exit code 42
# Python writes the target launch script path to data/.next_payload
NEXT_PAYLOAD_FILE="$DATA_DIR/.next_payload"

while true; do
    cd "$PAYLOAD_DIR"
    python3 loki_menu.py
    EXIT_CODE=$?

    # Exit code 42 = hand off to another payload
    if [ "$EXIT_CODE" -eq 42 ] && [ -f "$NEXT_PAYLOAD_FILE" ]; then
        NEXT_SCRIPT=$(cat "$NEXT_PAYLOAD_FILE")
        rm -f "$NEXT_PAYLOAD_FILE"
        if [ -f "$NEXT_SCRIPT" ]; then
            sh "$NEXT_SCRIPT"
            # Only loop back to Loki if launched app exits 42
            [ $? -eq 42 ] && continue
        fi
    fi

    # Exit code 99 = return to main menu (from pause menu)
    # bjorn_menu.py handles this internally, but as safety net
    if [ "$EXIT_CODE" -eq 99 ]; then
        continue
    fi

    break
done

exit 0
