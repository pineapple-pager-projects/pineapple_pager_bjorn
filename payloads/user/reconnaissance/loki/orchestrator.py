# orchestrator.py
# Description:
# This file, orchestrator.py, is the heuristic Loki brain, and it is responsible for coordinating and executing various network scanning and offensive security actions
# It manages the loading and execution of actions, handles retries for failed and successful actions, 
# and updates the status of the orchestrator.
#
# Key functionalities include:
# - Initializing and loading actions from a configuration file, including network and vulnerability scanners.
# - Managing the execution of actions on network targets, checking for open ports and handling retries based on success or failure.
# - Coordinating the execution of parent and child actions, ensuring actions are executed in a logical order.
# - Running the orchestrator cycle to continuously check for and execute actions on available network targets.
# - Handling and updating the status of the orchestrator, including scanning for new targets and performing vulnerability scans.
# - Implementing threading to manage concurrent execution of actions with a semaphore to limit active threads.
# - Logging events and errors to ensure maintainability and ease of debugging.
# - Handling graceful degradation by managing retries and idle states when no new targets are found.

import json
import importlib
import time
import logging
import sys
import os
import threading
import ipaddress
from datetime import datetime, timedelta
from actions.nmap_vuln_scanner import NmapVulnScanner
from init_shared import shared_data
from logger import Logger

logger = Logger(name="orchestrator.py", level=logging.INFO)

class Orchestrator:
    def __init__(self):
        """Initialise the orchestrator"""
        self.shared_data = shared_data
        self.actions = []  # List of actions to be executed
        self.standalone_actions = []  # List of standalone actions to be executed
        self.failed_scans_count = 0  # Count the number of failed scans
        self.network_scanner = None
        self.last_vuln_scan_time = datetime.min  # Set the last vulnerability scan time to the minimum datetime value
        self.load_actions()  # Load all actions from the actions file
        actions_loaded = [action.__class__.__name__ for action in self.actions + self.standalone_actions]  # Get the names of the loaded actions
        logger.info(f"Actions loaded: {actions_loaded}")
        self.semaphore = threading.Semaphore(10)  # Limit the number of active threads to 10

        # Read and validate attack ordering strategy
        valid_orders = ('spread', 'per_host', 'per_phase')
        self.attack_order = getattr(self.shared_data, 'attack_order', 'spread')
        if self.attack_order not in valid_orders:
            logger.warning(f"Invalid attack_order '{self.attack_order}', defaulting to 'spread'")
            self.attack_order = 'spread'
        logger.info(f"Attack order strategy: {self.attack_order}")

        # Get target network from environment (set by payload.sh)
        self.target_network = None
        env_ip = os.environ.get('BJORN_IP')
        if env_ip:
            scan_prefix = getattr(self.shared_data, 'scan_network_prefix', 24) or 24
            try:
                self.target_network = ipaddress.IPv4Network(f"{env_ip}/{scan_prefix}", strict=False)
                logger.info(f"Orchestrator target network: {self.target_network}")
                # Archive netkb if network changed
                self._archive_netkb_if_network_changed()
            except Exception as e:
                logger.error(f"Error parsing target network: {e}")

    def _archive_netkb_if_network_changed(self):
        """Archive netkb.csv on every Bjorn start for a fresh scan."""
        netkb_file = self.shared_data.netkbfile
        network_marker_file = os.path.join(self.shared_data.datadir, '.last_network')

        current_network = str(self.target_network)

        # Check if netkb has any data worth archiving
        has_data = False
        if os.path.exists(netkb_file):
            try:
                with open(netkb_file, 'r') as f:
                    lines = f.readlines()
                    # More than just the header = has data
                    has_data = len(lines) > 1
            except:
                pass

        # Archive if there's data
        if has_data:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_network = current_network.replace('/', '_')
            archive_name = f"netkb_{safe_network}_{timestamp}.csv"
            archive_path = os.path.join(self.shared_data.datadir, 'archives')
            os.makedirs(archive_path, exist_ok=True)
            archive_file = os.path.join(archive_path, archive_name)

            try:
                import shutil
                shutil.copy2(netkb_file, archive_file)
                logger.info(f"Archived netkb.csv to {archive_file}")
            except Exception as e:
                logger.error(f"Error archiving netkb.csv: {e}")

        # Clear netkb.csv if configured (default: keep previous hosts)
        if getattr(self.shared_data, 'clear_hosts_on_startup', False):
            try:
                with open(netkb_file, 'w', newline='') as f:
                    import csv
                    writer = csv.writer(f)
                    writer.writerow(['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports'])
                logger.info(f"Cleared netkb.csv for fresh scan on {current_network}")
            except Exception as e:
                logger.error(f"Error clearing netkb.csv: {e}")

        # Update the network marker
        try:
            with open(network_marker_file, 'w') as f:
                f.write(current_network)
        except Exception as e:
            logger.error(f"Error writing network marker: {e}")

    def is_ip_in_target_network(self, ip):
        """Check if an IP is within the target network range."""
        if not self.target_network:
            return True  # No filter if no target network set
        try:
            return ipaddress.IPv4Address(ip) in self.target_network
        except:
            return False

    def load_actions(self):
        """Load all actions from the actions file"""
        self.actions_dir = self.shared_data.actions_dir
        with open(self.shared_data.actions_file, 'r') as file:
            actions_config = json.load(file)
        for action in actions_config:
            module_name = action["b_module"]
            if module_name == 'scanning':
                self.load_scanner(module_name)
            elif module_name == 'nmap_vuln_scanner':
                self.load_nmap_vuln_scanner(module_name)
            else:
                self.load_action(module_name, action)

    def load_scanner(self, module_name):
        """Load the network scanner"""
        module = importlib.import_module(f'actions.{module_name}')
        b_class = getattr(module, 'b_class')
        self.network_scanner = getattr(module, b_class)(self.shared_data)

    def load_nmap_vuln_scanner(self, module_name):
        """Load the nmap vulnerability scanner"""
        self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)

    def load_action(self, module_name, action):
        """Load an action from the actions file"""
        module = importlib.import_module(f'actions.{module_name}')
        try:
            b_class = action["b_class"]
            action_instance = getattr(module, b_class)(self.shared_data)
            action_instance.action_name = b_class
            action_instance.port = action.get("b_port")
            action_instance.b_parent_action = action.get("b_parent")
            if action_instance.port == 0:
                self.standalone_actions.append(action_instance)
            else:
                self.actions.append(action_instance)
        except AttributeError as e:
            logger.error(f"Module {module_name} is missing required attributes: {e}")

    def _host_fully_exhausted(self, row, ports):
        """Check if all applicable actions on a host are done (success/no_creds/max retries)."""
        max_retries = getattr(self.shared_data, 'max_failed_retries', 3)
        for action in self.actions:
            if hasattr(action, 'port') and str(action.port) not in ports:
                continue
            # Check parent dependency
            if action.b_parent_action:
                parent_status = row.get(action.b_parent_action, "")
                if 'success' not in parent_status:
                    continue  # Parent hasn't succeeded, child won't run anyway
            action_key = action.action_name
            status = row.get(action_key, "")
            if not status:
                return False  # Never attempted
            if 'no_creds' in status:
                continue  # Permanently done
            if 'success' in status and not self.shared_data.retry_success_actions:
                continue  # Done, no retry
            if 'failed' in status:
                try:
                    fail_count = int(status.split('_')[1])
                    if fail_count >= max_retries:
                        continue  # Max retries reached
                except (ValueError, IndexError):
                    pass
                if not getattr(self.shared_data, 'retry_failed_actions', True):
                    continue  # Retry disabled
                return False  # Will be retried
            return False  # Some other state, not exhausted
        return True

    def process_alive_ips(self, current_data):
        """Process all IPs with alive status set to 1.

        Processes one host at a time - runs all applicable actions on a host
        before moving to the next host.
        """
        any_action_executed = False

        # Process one host at a time
        for row in current_data:
            if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                break  # Stop immediately when manual mode enabled or exit requested

            if row["Alive"] != '1':
                continue

            ip, ports = row["IPs"], row["Ports"].split(';')

            # Skip hosts where all actions are exhausted
            if self._host_fully_exhausted(row, ports):
                logger.debug(f"Host {ip} fully exhausted, skipping")
                continue

            logger.info(f"Processing host {ip}...")

            # Run all parent actions (bruteforce) on this host first
            if getattr(self.shared_data, 'brute_force_running', True):
                for action in self.actions:
                    if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                        break
                    if action.b_parent_action is not None:
                        continue  # Skip child actions for now

                    action_key = action.action_name
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            any_action_executed = True
                            self.shared_data.lokiorch_status = action_key

            # Now run all child actions (steal files) on this host
            if getattr(self.shared_data, 'file_steal_running', True):
                for action in self.actions:
                    if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                        break
                    if action.b_parent_action is None:
                        continue  # Skip parent actions

                    action_key = action.action_name
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            any_action_executed = True
                            self.shared_data.lokiorch_status = action_key

            # If any action was executed on this host, save and continue to next host
            if any_action_executed:
                self.shared_data.write_data(current_data)

        return any_action_executed

    def _run_vuln_scan_single(self, row, current_data):
        """Run vulnerability scan on a single host with retry logic. Returns True if scan executed."""
        if not getattr(self.shared_data, 'scan_vuln_running', True):
            return False

        status_key = "NmapVulnScanner"
        ip = row["IPs"]

        # Skip IPs not in the target network
        if not self.is_ip_in_target_network(ip):
            return False

        # Check existing vuln scan status for this host
        vuln_status = row.get(status_key, "")

        # Skip if already scanned successfully and no retry
        if 'success' in vuln_status:
            if not self.shared_data.retry_success_actions:
                return False
            try:
                last_time = datetime.strptime(
                    vuln_status.split('_')[1] + "_" + vuln_status.split('_')[2],
                    "%Y%m%d_%H%M%S"
                )
                if datetime.now() < last_time + timedelta(seconds=self.shared_data.success_retry_delay):
                    return False
            except (ValueError, IndexError):
                pass

        # Check failed status with retry limits
        if 'failed' in vuln_status and not getattr(self.shared_data, 'retry_failed_actions', True):
            return False
        if 'failed' in vuln_status:
            try:
                parts = vuln_status.split('_')
                fail_count = int(parts[1])
                last_time = datetime.strptime(parts[2] + "_" + parts[3], "%Y%m%d_%H%M%S")
                max_retries = getattr(self.shared_data, 'max_failed_retries', 3)
                if fail_count >= max_retries:
                    return False
                if datetime.now() < last_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                    return False
            except (ValueError, IndexError):
                pass

        # Execute vulnerability scan
        try:
            self.shared_data.lokiorch_status = "NmapVulnScanner"
            result = self.nmap_vuln_scanner.execute(ip, row, status_key)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[status_key] = f'success_{timestamp}'
            else:
                prev_count = 0
                if 'failed' in vuln_status:
                    try:
                        prev_count = int(vuln_status.split('_')[1])
                    except (ValueError, IndexError):
                        pass
                row[status_key] = f'failed_{prev_count + 1}_{timestamp}'
            self.shared_data.write_data(current_data)
            return True
        except Exception as e:
            logger.error(f"Vuln scan failed for {ip}: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            prev_count = 0
            if 'failed' in vuln_status:
                try:
                    prev_count = int(vuln_status.split('_')[1])
                except (ValueError, IndexError):
                    pass
            row[status_key] = f'failed_{prev_count + 1}_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def run_vuln_scans(self, current_data):
        """Run vulnerability scans on all alive hosts."""
        for row in current_data:
            if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                break
            if row["Alive"] != '1':
                continue
            self._run_vuln_scan_single(row, current_data)

    def process_per_host(self, current_data):
        """Complete ALL attacks (brute -> steal -> vuln) on each host before moving to the next."""
        any_action_executed = False

        for row in current_data:
            if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                break
            if row["Alive"] != '1':
                continue

            ip, ports = row["IPs"], row["Ports"].split(';')
            logger.info(f"[per_host] Processing host {ip}...")

            # Phase 1: parent actions (bruteforce)
            if getattr(self.shared_data, 'brute_force_running', True):
                for action in self.actions:
                    if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                        break
                    if action.b_parent_action is not None:
                        continue
                    action_key = action.action_name
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            any_action_executed = True
                            self.shared_data.lokiorch_status = action_key

            # Phase 2: child actions (file steal)
            if getattr(self.shared_data, 'file_steal_running', True):
                for action in self.actions:
                    if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                        break
                    if action.b_parent_action is None:
                        continue
                    action_key = action.action_name
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            any_action_executed = True
                            self.shared_data.lokiorch_status = action_key

            # Phase 3: vuln scan on this host
            if not self.shared_data.orchestrator_should_exit and not self.shared_data.manual_mode:
                if self._run_vuln_scan_single(row, current_data):
                    any_action_executed = True

            if any_action_executed:
                self.shared_data.write_data(current_data)

        return any_action_executed

    def process_per_phase(self, current_data):
        """Run each attack phase across ALL hosts before moving to the next phase."""
        any_action_executed = False

        # Phase 1: all parent actions (bruteforce) on all hosts
        if getattr(self.shared_data, 'brute_force_running', True):
            for row in current_data:
                if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                    break
                if row["Alive"] != '1':
                    continue
                ip, ports = row["IPs"], row["Ports"].split(';')
                for action in self.actions:
                    if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                        break
                    if action.b_parent_action is not None:
                        continue
                    action_key = action.action_name
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            any_action_executed = True
                            self.shared_data.lokiorch_status = action_key

        # Phase 2: all child actions (file steal) on all hosts
        if getattr(self.shared_data, 'file_steal_running', True):
            for row in current_data:
                if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                    break
                if row["Alive"] != '1':
                    continue
                ip, ports = row["IPs"], row["Ports"].split(';')
                for action in self.actions:
                    if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                        break
                    if action.b_parent_action is None:
                        continue
                    action_key = action.action_name
                    with self.semaphore:
                        if self.execute_action(action, ip, ports, row, action_key, current_data):
                            any_action_executed = True
                            self.shared_data.lokiorch_status = action_key

        # Phase 3: vuln scans on all hosts
        self.run_vuln_scans(current_data)

        if any_action_executed:
            self.shared_data.write_data(current_data)

        return any_action_executed

    def execute_action(self, action, ip, ports, row, action_key, current_data):
        """Execute an action on a target"""
        # Skip IPs not in the target network
        if not self.is_ip_in_target_network(ip):
            return False

        if hasattr(action, 'port') and str(action.port) not in ports:
            return False

        # Check parent action status
        if action.b_parent_action:
            parent_status = row.get(action.b_parent_action, "")
            if 'success' not in parent_status:
                return False  # Skip child action if parent action has not succeeded

        # Check if the action is already successful and if retries are disabled for successful actions
        action_status = row.get(action_key, "")
        if 'success' in action_status:
            if not self.shared_data.retry_success_actions:
                return False
            else:
                try:
                    last_success_time = datetime.strptime(action_status.split('_')[1] + "_" + action_status.split('_')[2], "%Y%m%d_%H%M%S")
                    if datetime.now() < last_success_time + timedelta(seconds=self.shared_data.success_retry_delay):
                        retry_in_seconds = (last_success_time + timedelta(seconds=self.shared_data.success_retry_delay) - datetime.now()).seconds
                        formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                        logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to success retry delay, retry possible in: {formatted_retry_in}")
                        return False  # Skip if the success retry delay has not passed
                except ValueError as ve:
                    logger.error(f"Error parsing last success time for {action.action_name}: {ve}")

        # Skip permanently if all credentials were exhausted (no point retrying same list)
        if 'no_creds' in action_status:
            logger.info(f"Skipping action {action.action_name} for {ip}:{action.port} - credentials exhausted")
            return False

        # Check failed status: format is failed_{count}_{timestamp}
        last_failed_time_str = row.get(action_key, "")
        if 'failed' in last_failed_time_str:
            if not getattr(self.shared_data, 'retry_failed_actions', True):
                return False
            try:
                parts = last_failed_time_str.split('_')
                # Parse count and timestamp from failed_{count}_{YYYYMMDD}_{HHMMSS}
                fail_count = int(parts[1])
                last_failed_time = datetime.strptime(parts[2] + "_" + parts[3], "%Y%m%d_%H%M%S")
                max_retries = getattr(self.shared_data, 'max_failed_retries', 3)
                if fail_count >= max_retries:
                    logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} - max retries ({max_retries}) reached")
                    return False
                if datetime.now() < last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                    retry_in_seconds = (last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay) - datetime.now()).seconds
                    formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                    logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to failed retry delay ({fail_count}/{max_retries}), retry possible in: {formatted_retry_in}")
                    return False
            except (ValueError, IndexError):
                # Legacy format failed_{timestamp} — treat as first failure
                try:
                    last_failed_time = datetime.strptime(last_failed_time_str.split('_')[1] + "_" + last_failed_time_str.split('_')[2], "%Y%m%d_%H%M%S")
                    if datetime.now() < last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                        retry_in_seconds = (last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay) - datetime.now()).seconds
                        formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                        logger.warning(f"Skipping action {action.action_name} for {ip}:{action.port} due to failed retry delay, retry possible in: {formatted_retry_in}")
                        return False
                except (ValueError, IndexError):
                    pass

        try:
            logger.info(f"Executing action {action.action_name} for {ip}:{action.port}")
            self.shared_data.lokistatustext2 = ip
            self.shared_data.attacksnbr += 1  # Increment attack counter
            result = action.execute(ip, str(action.port), row, action_key)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
            elif result == 'no_creds_found':
                row[action_key] = f'no_creds_{timestamp}'
            else:
                # Increment failure count
                prev_count = 0
                prev_status = row.get(action_key, "")
                if 'failed' in prev_status:
                    try:
                        prev_count = int(prev_status.split('_')[1])
                    except (ValueError, IndexError):
                        pass
                row[action_key] = f'failed_{prev_count + 1}_{timestamp}'
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            prev_count = 0
            prev_status = row.get(action_key, "")
            if 'failed' in prev_status:
                try:
                    prev_count = int(prev_status.split('_')[1])
                except (ValueError, IndexError):
                    pass
            row[action_key] = f'failed_{prev_count + 1}_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def execute_standalone_action(self, action, current_data):
        """Execute a standalone action"""
        row = next((r for r in current_data if r["MAC Address"] == "STANDALONE"), None)
        if not row:
            row = {
                "MAC Address": "STANDALONE",
                "IPs": "STANDALONE",
                "Hostnames": "STANDALONE",
                "Ports": "0",
                "Alive": "0"
            }
            current_data.append(row)

        action_key = action.action_name
        if action_key not in row:
            row[action_key] = ""

        # Check if the action is already successful and if retries are disabled for successful actions
        if 'success' in row[action_key]:
            if not self.shared_data.retry_success_actions:
                return False
            else:
                try:
                    last_success_time = datetime.strptime(row[action_key].split('_')[1] + "_" + row[action_key].split('_')[2], "%Y%m%d_%H%M%S")
                    if datetime.now() < last_success_time + timedelta(seconds=self.shared_data.success_retry_delay):
                        retry_in_seconds = (last_success_time + timedelta(seconds=self.shared_data.success_retry_delay) - datetime.now()).seconds
                        formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                        logger.warning(f"Skipping standalone action {action.action_name} due to success retry delay, retry possible in: {formatted_retry_in}")
                        return False  # Skip if the success retry delay has not passed
                except ValueError as ve:
                    logger.error(f"Error parsing last success time for {action.action_name}: {ve}")

        # Skip permanently if all credentials were exhausted
        if 'no_creds' in row.get(action_key, ""):
            logger.info(f"Skipping standalone action {action.action_name} - credentials exhausted")
            return False

        # Check failed status: format is failed_{count}_{timestamp}
        last_failed_time_str = row.get(action_key, "")
        if 'failed' in last_failed_time_str:
            if not getattr(self.shared_data, 'retry_failed_actions', True):
                return False
            try:
                parts = last_failed_time_str.split('_')
                fail_count = int(parts[1])
                last_failed_time = datetime.strptime(parts[2] + "_" + parts[3], "%Y%m%d_%H%M%S")
                max_retries = getattr(self.shared_data, 'max_failed_retries', 3)
                if fail_count >= max_retries:
                    logger.warning(f"Skipping standalone action {action.action_name} - max retries ({max_retries}) reached")
                    return False
                if datetime.now() < last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                    retry_in_seconds = (last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay) - datetime.now()).seconds
                    formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                    logger.warning(f"Skipping standalone action {action.action_name} due to failed retry delay ({fail_count}/{max_retries}), retry possible in: {formatted_retry_in}")
                    return False
            except (ValueError, IndexError):
                try:
                    last_failed_time = datetime.strptime(last_failed_time_str.split('_')[1] + "_" + last_failed_time_str.split('_')[2], "%Y%m%d_%H%M%S")
                    if datetime.now() < last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay):
                        retry_in_seconds = (last_failed_time + timedelta(seconds=self.shared_data.failed_retry_delay) - datetime.now()).seconds
                        formatted_retry_in = str(timedelta(seconds=retry_in_seconds))
                        logger.warning(f"Skipping standalone action {action.action_name} due to failed retry delay, retry possible in: {formatted_retry_in}")
                        return False
                except (ValueError, IndexError):
                    pass

        try:
            logger.info(f"Executing standalone action {action.action_name}")
            result = action.execute()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                logger.info(f"Standalone action {action.action_name} executed successfully")
            elif result == 'no_creds_found':
                row[action_key] = f'no_creds_{timestamp}'
                logger.info(f"Standalone action {action.action_name} - no credentials found")
            else:
                prev_count = 0
                prev_status = row.get(action_key, "")
                if 'failed' in prev_status:
                    try:
                        prev_count = int(prev_status.split('_')[1])
                    except (ValueError, IndexError):
                        pass
                row[action_key] = f'failed_{prev_count + 1}_{timestamp}'
                logger.error(f"Standalone action {action.action_name} failed ({prev_count + 1}/{getattr(self.shared_data, 'max_failed_retries', 3)})")
            self.shared_data.write_data(current_data)
            return result == 'success'
        except Exception as e:
            logger.error(f"Standalone action {action.action_name} failed: {e}")
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            prev_count = 0
            prev_status = row.get(action_key, "")
            if 'failed' in prev_status:
                try:
                    prev_count = int(prev_status.split('_')[1])
                except (ValueError, IndexError):
                    pass
            row[action_key] = f'failed_{prev_count + 1}_{timestamp}'
            self.shared_data.write_data(current_data)
            return False

    def run(self):
        """Run the orchestrator cycle to execute actions"""
        try:
            # Run the scanner a first time to get the initial data (skip if manual mode)
            if not self.shared_data.manual_mode:
                self.shared_data.lokiorch_status = "NetworkScanner"
                self.shared_data.lokistatustext2 = "First scan..."
                self.network_scanner.scan()
                self.shared_data.lokistatustext2 = ""

            while not self.shared_data.orchestrator_should_exit and not self.shared_data.manual_mode:
                current_data = self.shared_data.read_data()
                action_retry_pending = False

                # Process hosts using the configured attack order strategy
                if self.attack_order == 'per_host':
                    any_action_executed = self.process_per_host(current_data)
                elif self.attack_order == 'per_phase':
                    any_action_executed = self.process_per_phase(current_data)
                else:  # 'spread' (default)
                    any_action_executed = self.process_alive_ips(current_data)
                    self.run_vuln_scans(current_data)

                if not any_action_executed:
                    self.shared_data.lokiorch_status = "IDLE"
                    self.shared_data.lokistatustext2 = ""
                    if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                        continue
                    logger.info("No available targets. Running network scan...")
                    if self.network_scanner:
                        self.shared_data.lokiorch_status = "NetworkScanner"
                        self.network_scanner.scan()
                        if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                            continue
                        # Re-read updated data after scan and re-run with same strategy
                        current_data = self.shared_data.read_data()
                        if self.attack_order == 'per_host':
                            any_action_executed = self.process_per_host(current_data)
                        elif self.attack_order == 'per_phase':
                            any_action_executed = self.process_per_phase(current_data)
                        else:
                            any_action_executed = self.process_alive_ips(current_data)

                    else:
                        logger.warning("No network scanner available.")
                    self.failed_scans_count += 1
                    if self.failed_scans_count >= 1:
                        for action in self.standalone_actions:
                            if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                                break
                            with self.semaphore:
                                if self.execute_standalone_action(action, current_data):
                                    self.failed_scans_count = 0
                                    break
                        idle_start_time = datetime.now()
                        idle_end_time = idle_start_time + timedelta(seconds=self.shared_data.scan_interval)
                        self.shared_data.lokiorch_status = "IDLE"
                        self.shared_data.lokistatustext2 = ""
                        logger.info(f"No new targets found. Next scan in {self.shared_data.scan_interval} seconds...")
                        while datetime.now() < idle_end_time:
                            if self.shared_data.orchestrator_should_exit or self.shared_data.manual_mode:
                                break
                            time.sleep(5)  # Check exit signal every 5 seconds
                        self.failed_scans_count = 0
                        continue
                else:
                    self.failed_scans_count = 0
                    action_retry_pending = True

                if action_retry_pending:
                    self.failed_scans_count = 0

        except Exception as e:
            logger.error(f"ORCHESTRATOR CRASHED: {e}")
            import traceback
            logger.error(traceback.format_exc())
            # Re-raise so Bjorn main loop knows to restart
            raise

if __name__ == "__main__":
    orchestrator = Orchestrator()
    orchestrator.run()
