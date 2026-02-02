#!/bin/bash
# Title: Bjorn
# Description: Autonomous network reconnaissance companion (Tamagotchi-style)
# Author: infinition (ported by brAinphreAk)
# Version: 1.0
# Category: Reconnaissance

PAYLOAD_DIR="/root/payloads/user/reconnaissance/pager_bjorn"

#
# Setup paths for Python and shared library
#
export PYTHONPATH="$PAYLOAD_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="$PAYLOAD_DIR:$LD_LIBRARY_PATH"

#
# Check for Python3 + required modules
#
check_python() {
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
        LOG "red" "=== PYTHON3 REQUIRED ==="
        LOG ""
        if [ "$NEED_PYTHON" = true ]; then
            LOG "Python3 is not installed."
        else
            LOG "Python3-ctypes is not installed."
        fi
        LOG ""
        LOG "Bjorn requires Python3 + ctypes for pagerctl."
        LOG ""
        LOG "green" "GREEN = Install Python3 (requires internet)"
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
                    LOG "Installing Python3 + ctypes..."
                    opkg install python3 python3-ctypes 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                    LOG ""
                    if command -v python3 >/dev/null 2>&1 && python3 -c "import ctypes" 2>/dev/null; then
                        LOG "green" "Python3 installed successfully!"
                        sleep 1
                        return 0
                    else
                        LOG "red" "Failed to install Python3"
                        LOG "Check internet connection."
                        sleep 2
                        return 1
                    fi
                    ;;
                "RED"|"B")
                    LOG "Exiting."
                    exit 0
                    ;;
            esac
        done
    fi
    return 0
}

#
# Check for Bjorn dependencies
#
check_dependencies() {
    LOG ""
    LOG "Checking dependencies..."

    MISSING=""

    # Check for nmap
    if ! command -v nmap >/dev/null 2>&1; then
        MISSING="$MISSING nmap"
    fi

    # Check for python-nmap
    if ! python3 -c "import nmap" 2>/dev/null; then
        MISSING="$MISSING python-nmap"
    fi

    # Check for paramiko (for SSH)
    if ! python3 -c "import paramiko" 2>/dev/null; then
        MISSING="$MISSING paramiko"
    fi

    if [ -n "$MISSING" ]; then
        LOG ""
        LOG "red" "Missing dependencies:$MISSING"
        LOG ""
        LOG "green" "GREEN = Install dependencies (requires internet)"
        LOG "red" "RED   = Continue anyway"
        LOG ""

        BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
        case "$BUTTON" in
            "GREEN"|"A")
                LOG ""
                LOG "Installing dependencies..."
                LOG ""
                opkg update 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                opkg install nmap python3-pip 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                LOG ""
                LOG "Installing Python packages via pip..."
                pip3 install python-nmap paramiko pysmb pymysql 2>&1 | while IFS= read -r line; do LOG "  $line"; done
                LOG ""
                LOG "green" "Dependencies installed!"
                sleep 1
                ;;
            *)
                LOG "Continuing without some dependencies..."
                sleep 1
                ;;
        esac
    else
        LOG "green" "All dependencies found!"
    fi
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

# Check Python first (required)
check_python || exit 1

# Check if libpagerctl.so exists
if [ ! -f "$PAYLOAD_DIR/libpagerctl.so" ]; then
    LOG ""
    LOG "red" "ERROR: libpagerctl.so not found!"
    LOG ""
    LOG "Build and deploy from your computer:"
    LOG "  cd pagerctl && make remote-build"
    LOG "  Then copy libpagerctl.so to pager_bjorn/"
    LOG ""
    LOG "Press any button to exit..."
    WAIT_FOR_INPUT >/dev/null 2>&1
    exit 1
fi

# Show menu
LOG ""
LOG "green" "=========================================="
LOG "green" "              BJORN"
LOG "green" "   Autonomous Network Reconnaissance"
LOG "green" "=========================================="
LOG ""
LOG "Tamagotchi-style hacking companion."
LOG "Scans networks, finds vulnerabilities,"
LOG "and collects credentials automatically."
LOG ""
LOG "green" "  GREEN = Start Bjorn"
LOG "  UP    = Check Dependencies"
LOG "red" "  RED   = Exit"
LOG ""

# Wait for selection
BUTTON=$(WAIT_FOR_INPUT 2>/dev/null)
case "$BUTTON" in
    "GREEN"|"A")
        LOG ""
        LOG "Starting Bjorn..."
        /etc/init.d/pineapplepager stop 2>/dev/null
        sleep 0.3
        cd "$PAYLOAD_DIR"
        python3 Bjorn.py
        /etc/init.d/pineapplepager start 2>/dev/null
        ;;
    "UP")
        check_dependencies
        # Re-show menu
        exec "$0"
        ;;
    "RED"|"B"|*)
        LOG ""
        LOG "Exiting."
        ;;
esac

exit 0
