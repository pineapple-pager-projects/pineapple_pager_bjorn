#Loki.py
# This script defines the main execution flow for the Loki application. It initializes and starts
# various components such as network scanning, display, and web server functionalities. The Loki
# class manages the primary operations, including initiating network scans and orchestrating tasks.
# The script handles startup delays, checks for Wi-Fi connectivity, and coordinates the execution of
# scanning and orchestrator tasks using semaphores to limit concurrent threads. It also sets up
# signal handlers to ensure a clean exit when the application is terminated.

# Functions:
# - handle_exit:  handles the termination of the main and display threads.
# - handle_exit_webserver:  handles the termination of the web server thread.
# - is_wifi_connected: Checks for Wi-Fi connectivity using the nmcli command.

# The script starts by loading shared data configurations, then initializes and sta
# Loki.py

# Add local lib directory to Python path for self-contained payload
import sys
import os
_lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lib')
if os.path.exists(_lib_path) and _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

# Fix OpenSSL legacy provider issue for cryptography/paramiko
os.environ['CRYPTOGRAPHY_OPENSSL_NO_LEGACY'] = '1'

import threading
import signal
import logging
import time
import sys
import subprocess
from init_shared import shared_data
from display import Display, handle_exit_display
from comment import Commentaireia
from orchestrator import Orchestrator
from logger import Logger

# Import web server
from webapp import web_thread, handle_exit_web

logger = Logger(name="Loki.py", level=logging.INFO)

class Loki:
    """Main class for Loki. Manages the primary operations of the application."""
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.commentaire_ia = Commentaireia()
        self.orchestrator_thread = None
        self.orchestrator = None
        self._orchestrator_lock = threading.Lock()  # Prevent race condition on start

    def run(self):
        """Main loop for Loki. Waits for Wi-Fi connection and starts Orchestrator."""
        # Wait for startup delay if configured in shared data
        if hasattr(self.shared_data, 'startup_delay') and self.shared_data.startup_delay > 0:
            logger.info(f"Waiting for startup delay: {self.shared_data.startup_delay} seconds")
            time.sleep(self.shared_data.startup_delay)

        # Main loop to keep Bjorn running
        while not self.shared_data.should_exit:
            if not self.shared_data.manual_mode:
                self.check_and_start_orchestrator()
            time.sleep(10)  # Main loop idle waiting



    def check_and_start_orchestrator(self):
        """Check Wi-Fi and start the orchestrator if connected."""
        if self.is_wifi_connected():
            self.wifi_connected = True
            if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                self.start_orchestrator()
        else:
            self.wifi_connected = False
            logger.info("Waiting for Wi-Fi connection to start Orchestrator...")

    def start_orchestrator(self):
        """Start the orchestrator thread."""
        with self._orchestrator_lock:  # Prevent race condition
            self.is_wifi_connected()  # reCheck if Wi-Fi is connected before starting the orchestrator
            if self.wifi_connected:  # Check if Wi-Fi is connected before starting the orchestrator
                if self.orchestrator_thread is None or not self.orchestrator_thread.is_alive():
                    logger.info("Starting Orchestrator thread...")
                    self.shared_data.orchestrator_should_exit = False
                    self.shared_data.manual_mode = False
                    self.orchestrator = Orchestrator()
                    self.orchestrator_thread = threading.Thread(target=self.orchestrator.run)
                    self.orchestrator_thread.start()
                    logger.info("Orchestrator thread started, automatic mode activated.")
                else:
                    logger.info("Orchestrator thread is already running.")
            else:
                logger.warning("Cannot start Orchestrator: Wi-Fi is not connected.")

    def stop_orchestrator(self):
        """Stop the orchestrator thread."""
        self.shared_data.manual_mode = True
        logger.info("Stop button pressed. Manual mode activated & Stopping Orchestrator...")
        if self.orchestrator_thread is not None and self.orchestrator_thread.is_alive():
            logger.info("Stopping Orchestrator thread...")
            self.shared_data.orchestrator_should_exit = True
            self.orchestrator_thread.join()
            logger.info("Orchestrator thread stopped.")
            self.shared_data.lokiorch_status = "IDLE"
            self.shared_data.lokistatustext2 = ""
            self.shared_data.manual_mode = True
        else:
            logger.info("Orchestrator thread is not running.")

    def is_wifi_connected(self):
        """Checks for Wi-Fi connectivity using ip link (Pager compatible)."""
        try:
            # Check if wlan0cli (client WiFi) interface is UP
            result = subprocess.run(['ip', 'link', 'show', 'wlan0cli'],
                                    capture_output=True, text=True, timeout=5)
            # Check if interface is UP and has carrier
            self.wifi_connected = 'state UP' in result.stdout
            if not self.wifi_connected:
                # Also check br-lan as fallback (ethernet bridge)
                result = subprocess.run(['ip', 'link', 'show', 'br-lan'],
                                        capture_output=True, text=True, timeout=5)
                self.wifi_connected = 'state UP' in result.stdout
            return self.wifi_connected
        except Exception as e:
            logger.debug(f"WiFi check error: {e}")
            self.wifi_connected = False
            return False

    
    @staticmethod
    def start_display():
        """Start the display thread"""
        display = Display(shared_data)
        display_thread = threading.Thread(target=display.run)
        display_thread.start()
        return display_thread

def handle_exit(sig, frame, display_thread, loki_thread, web_thread=None):
    """Handles the termination of the main, display, and web threads."""
    shared_data.should_exit = True
    shared_data.orchestrator_should_exit = True  # Ensure orchestrator stops
    shared_data.display_should_exit = True  # Ensure display stops
    shared_data.webapp_should_exit = True  # Ensure web server stops
    # Kill any running nmap subprocesses
    try:
        subprocess.run(['killall', 'nmap'], capture_output=True, timeout=5)
    except Exception:
        pass
    handle_exit_display(sig, frame, display_thread)
    if display_thread.is_alive():
        display_thread.join()
    if loki_thread.is_alive():
        loki_thread.join()
    if web_thread and web_thread.is_alive():
        web_thread.join()
    logger.info("Main loop finished. Clean exit.")
    sys.exit(0)  # Used sys.exit(0) instead of exit(0)



if __name__ == "__main__":
    logger.debug("Starting threads")

    try:
        logger.debug("Loading shared data config...")
        shared_data.load_config()

        logger.info("Starting display thread...")
        shared_data.display_should_exit = False  # Initialize display should_exit
        display_thread = Loki.start_display()

        logger.info("Starting Loki thread...")
        loki = Loki(shared_data)
        shared_data.loki_instance = loki
        loki_thread = threading.Thread(target=loki.run)
        loki_thread.start()

        # Start web server (conditional on BJORN_WEB_UI env var)
        web_ui_setting = os.environ.get('BJORN_WEB_UI', 'on').lower()
        if web_ui_setting != 'off':
            logger.info("Starting the web server...")
            shared_data.webapp_should_exit = False
            web_thread.start()
        else:
            logger.info("Web server disabled by menu setting")
            web_thread = None

        signal.signal(signal.SIGINT, lambda sig, frame: handle_exit(sig, frame, display_thread, loki_thread, web_thread))
        signal.signal(signal.SIGTERM, lambda sig, frame: handle_exit(sig, frame, display_thread, loki_thread, web_thread))

    except Exception as e:
        logger.error(f"An exception occurred during thread start: {e}")
        handle_exit_display(signal.SIGINT, None)
        exit(1)
