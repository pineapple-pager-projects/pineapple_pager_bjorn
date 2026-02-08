#utils.py

import json
import subprocess
import os
import json
import csv
import zipfile
import uuid
import cgi
import io
import importlib
import logging
from datetime import datetime
from logger import Logger
from urllib.parse import unquote
from actions.nmap_vuln_scanner import NmapVulnScanner



logger = Logger(name="utils.py", level=logging.INFO)


class WebUtils:
    def __init__(self, shared_data, logger):
        self.shared_data = shared_data
        self.logger = logger
        self.actions = None  # List that contains all actions
        self.standalone_actions = None  # List that contains all standalone actions

    def load_actions(self):
        """Load all actions from the actions file (only used by orchestrator)"""
        if self.actions is None or self.standalone_actions is None:
            self.actions = []
            self.standalone_actions = []
            self.actions_dir = self.shared_data.actions_dir
            with open(self.shared_data.actions_file, 'r') as file:
                actions_config = json.load(file)
            for action in actions_config:
                module_name = action["b_module"]
                if module_name == 'scanning':
                    self._load_scanner_module(module_name)
                elif module_name == 'nmap_vuln_scanner':
                    self._load_nmap_module()
                else:
                    self._load_action_module(module_name, action)

    def ensure_network_scanner(self):
        """Load only the network scanner if not already loaded"""
        if not hasattr(self, 'network_scanner') or self.network_scanner is None:
            self._load_scanner_module('scanning')

    def ensure_nmap_scanner(self):
        """Load only the nmap vuln scanner if not already loaded"""
        if not hasattr(self, 'nmap_vuln_scanner') or self.nmap_vuln_scanner is None:
            self._load_nmap_module()

    def ensure_single_action(self, action_class):
        """Load only a specific action module if not already loaded"""
        # Initialize actions list if needed
        if self.actions is None:
            self.actions = []
        if self.standalone_actions is None:
            self.standalone_actions = []

        # Check if action is already loaded
        existing = next((a for a in self.actions if a.action_name == action_class), None)
        if existing:
            return existing
        existing = next((a for a in self.standalone_actions if a.action_name == action_class), None)
        if existing:
            return existing

        # Find the action config and load only that module
        with open(self.shared_data.actions_file, 'r') as file:
            actions_config = json.load(file)
        for action in actions_config:
            if action.get("b_class") == action_class:
                module_name = action["b_module"]
                self._load_action_module(module_name, action)
                # Return the newly loaded action
                return next((a for a in self.actions if a.action_name == action_class),
                           next((a for a in self.standalone_actions if a.action_name == action_class), None))
        return None

    def _load_scanner_module(self, module_name):
        """Internal: Load the network scanner module"""
        module = importlib.import_module(f'actions.{module_name}')
        b_class = getattr(module, 'b_class')
        self.network_scanner = getattr(module, b_class)(self.shared_data)

    def _load_nmap_module(self):
        """Internal: Load the nmap vulnerability scanner"""
        self.nmap_vuln_scanner = NmapVulnScanner(self.shared_data)

    def _load_action_module(self, module_name, action):
        """Internal: Load a single action module"""
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
            self.logger.error(f"Module {module_name} is missing required attributes: {e}")

    def get_available_networks(self, handler):
        """Get all available network interfaces and their subnets."""
        try:
            import re
            import ipaddress
            networks = []

            # Get all interfaces with IP addresses
            result = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                current_iface = None
                for line in result.stdout.split('\n'):
                    # Match interface line: "2: wlan0: <BROADCAST..." or "3: br-lan: <..."
                    # Use [^\s:]+ to match interface names with hyphens
                    iface_match = re.match(r'\d+:\s+([^\s:]+):', line)
                    if iface_match:
                        current_iface = iface_match.group(1)
                    # Match inet line: "    inet 10.0.0.110/24 brd..."
                    inet_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)', line)
                    if inet_match and current_iface:
                        ip = inet_match.group(1)
                        # Skip localhost
                        if ip.startswith('127.') or current_iface == 'lo':
                            continue
                        # Always use /24 for scanning (larger subnets take too long)
                        try:
                            network = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                            # Get base of network (e.g., "10.0.0" from "10.0.0.0/24")
                            net_base = '.'.join(ip.split('.')[:3])
                            networks.append({
                                'interface': current_iface,
                                'ip': ip,
                                'network': str(network),
                                'display': f"{net_base}.x ({current_iface})"
                            })
                        except:
                            pass

            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({'networks': networks}).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error getting available networks: {e}")
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({'error': str(e)}).encode('utf-8'))

    def serve_netkb_data_json(self, handler):
        try:
            netkb_file = self.shared_data.netkbfile

            # Load valid action names and their default ports from actions.json
            valid_actions = []
            action_ports = {}  # Map action name to its default port
            port_to_actions = {}  # Map port to list of actions (for auto-select)

            # Display names for actions (friendly names)
            action_display_names = {
                'FTPBruteforce': 'FTP Brute Force',
                'StealFilesFTP': 'FTP Steal Files',
                'RDPBruteforce': 'RDP Brute Force',
                'SMBBruteforce': 'SMB Brute Force',
                'StealFilesSMB': 'SMB Steal Files',
                'SQLBruteforce': 'SQL Brute Force',
                'StealDataSQL': 'SQL Steal Data',
                'SSHBruteforce': 'SSH Brute Force',
                'StealFilesSSH': 'SSH Steal Files',
                'TelnetBruteforce': 'Telnet Brute Force',
                'StealFilesTelnet': 'Telnet Steal Files',
                'NetworkScanner': 'Network Scanner',
                'NmapVulnScanner': 'Nmap Vuln Scanner',
            }

            # Define order: group by protocol, brute force first then steal
            action_order = [
                'FTPBruteforce', 'StealFilesFTP',
                'RDPBruteforce',
                'SMBBruteforce', 'StealFilesSMB',
                'SQLBruteforce', 'StealDataSQL',
                'SSHBruteforce', 'StealFilesSSH',
                'TelnetBruteforce', 'StealFilesTelnet',
            ]

            try:
                with open(self.shared_data.actions_file, 'r') as f:
                    actions_config = json.load(f)
                    for action in actions_config:
                        b_class = action.get('b_class')
                        b_port = action.get('b_port')
                        # Include actions that have a specific port (not None, not 0)
                        if b_class and b_port and b_port != 0:
                            valid_actions.append(b_class)
                            action_ports[b_class] = b_port
                            # Build reverse mapping: port -> actions
                            if b_port not in port_to_actions:
                                port_to_actions[b_port] = []
                            port_to_actions[b_port].append(b_class)
            except Exception as e:
                logger.error(f"Error loading actions.json: {e}")

            # Sort actions by defined order
            def action_sort_key(action):
                try:
                    return action_order.index(action)
                except ValueError:
                    return 999  # Unknown actions go last
            valid_actions.sort(key=action_sort_key)

            # Read netkb file - handle case where file doesn't exist or is empty
            data = []
            if os.path.exists(netkb_file):
                try:
                    with open(netkb_file, 'r', encoding='utf-8') as file:
                        reader = csv.DictReader(file)
                        # Get all rows - only exclude if Alive is explicitly '0'
                        for row in reader:
                            alive = row.get('Alive', '')
                            # Include if Alive is empty, '1', or column doesn't exist
                            if alive != '0':
                                data.append(row)
                except Exception as e:
                    logger.error(f"Error reading netkb file: {e}")

            # Parse ports - handle both comma and semicolon separators
            def parse_ports(ports_str):
                if not ports_str:
                    return []
                # Split by semicolon first, then by comma for each part
                ports = []
                for part in ports_str.replace(',', ';').split(';'):
                    part = part.strip()
                    # Only include if it looks like a valid port number
                    if part and part.isdigit() and int(part) > 1 and int(part) <= 65535:
                        ports.append(part)
                return ports

            def get_ports_from_row(row):
                """Try multiple columns to find actual port data."""
                # Try columns in order of likelihood
                for col in ['Ports', 'First Seen', 'Last Seen']:
                    ports_str = row.get(col, '')
                    ports = parse_ports(ports_str)
                    if len(ports) > 0:
                        return ports
                return []

            response_data = {
                'ips': [row.get('IPs', row.get('IP Address', '')) for row in data],
                'ports': {row.get('IPs', row.get('IP Address', '')): get_ports_from_row(row) for row in data},
                'actions': valid_actions,
                'action_ports': action_ports,  # Map action -> port
                'port_to_actions': port_to_actions,  # Map port -> [actions] for auto-select
                'action_display_names': action_display_names  # Friendly names
            }

            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps(response_data).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def execute_manual_attack(self, handler):
        try:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length).decode('utf-8')
            params = json.loads(post_data)
            ip = params.get('ip', '')
            port = params.get('port', '')
            action_class = params['action']
            network = params.get('network', '')  # Optional: specific network to scan

            self.logger.info(f"Received request to execute {action_class} on {ip}:{port}")

            # Keep orchestrator in manual mode (paused) but allow this action to run
            self.shared_data.manual_mode = True
            # Save and temporarily clear exit flag so manual attack can run
            saved_exit_flag = self.shared_data.orchestrator_should_exit
            self.shared_data.orchestrator_should_exit = False

            # Handle NetworkScanner specially - it scans the network, doesn't need an IP
            if action_class == 'NetworkScanner':
                self.ensure_network_scanner()  # Only load scanner module
                if network:
                    self.logger.info(f"Executing NetworkScanner on {network}...")
                else:
                    self.logger.info("Executing NetworkScanner to discover hosts...")
                import threading
                scan_thread = threading.Thread(target=self.network_scanner.scan, args=(network,) if network else ())
                scan_thread.start()
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "success", "message": f"Network scan started{' on ' + network if network else ''}"}).encode('utf-8'))
                return

            # Handle PortScanner - scan ports on a specific IP
            if action_class == 'PortScanner':
                if not ip:
                    raise Exception("PortScanner requires an IP address")
                self.ensure_network_scanner()  # Only load scanner module
                self.logger.info(f"Executing PortScanner on {ip}...")
                import threading
                scan_thread = threading.Thread(target=self.scan_ports_single_ip, args=(ip,))
                scan_thread.start()
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "success", "message": f"Port scan started on {ip}"}).encode('utf-8'))
                return

            # Handle NmapVulnScanner - can run on specific IP or all hosts
            if action_class == 'NmapVulnScanner':
                self.ensure_nmap_scanner()  # Only load nmap module
                self.logger.info(f"Executing NmapVulnScanner on {ip if ip else 'all hosts'}...")
                if ip:
                    result = self.nmap_vuln_scanner.execute(ip=ip)
                else:
                    result = self.nmap_vuln_scanner.execute()
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                if result == 'success':
                    handler.wfile.write(json.dumps({"status": "success", "message": "Vulnerability scan completed"}).encode('utf-8'))
                else:
                    handler.wfile.write(json.dumps({"status": "error", "message": "Vulnerability scan failed"}).encode('utf-8'))
                return

            # Regular action - load only the specific action needed
            action_instance = self.ensure_single_action(action_class)
            if action_instance is None:
                raise Exception(f"Action class {action_class} not found")

            # Load current data
            current_data = self.shared_data.read_data()
            row = next((r for r in current_data if r["IPs"] == ip), None)

            if row is None:
                raise Exception(f"No data found for IP: {ip}")

            action_key = action_instance.action_name
            self.logger.info(f"[LIFECYCLE] {action_class} STARTED on {ip}:{port}")
            start_time = datetime.now()
            result = action_instance.execute(ip, port, row, action_key)
            duration = (datetime.now() - start_time).total_seconds()

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            if result == 'success':
                row[action_key] = f'success_{timestamp}'
                self.logger.info(f"[LIFECYCLE] {action_class} ENDED (success) for {ip}:{port} in {duration:.1f}s")
            else:
                row[action_key] = f'failed_{timestamp}'
                self.logger.info(f"[LIFECYCLE] {action_class} ENDED (failure) for {ip}:{port} in {duration:.1f}s")
            self.shared_data.write_data(current_data)

            # Restore exit flag after manual attack
            self.shared_data.orchestrator_should_exit = saved_exit_flag

            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "Manual attack executed"}).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error executing manual attack: {e}")
            # Restore exit flag on error too
            try:
                self.shared_data.orchestrator_should_exit = saved_exit_flag
            except:
                pass
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def scan_ports_single_ip(self, ip):
        """
        Scan ports on a single IP address and update the netkb file.
        Returns 'success' or 'failed'.
        """
        import socket
        import threading

        try:
            self.logger.info(f"[LIFECYCLE] PortScanner STARTED on {ip}")
            start_time = datetime.now()

            # Get port range from shared_data
            portstart = getattr(self.shared_data, 'portstart', 1)
            portend = getattr(self.shared_data, 'portend', 100)
            extra_ports = getattr(self.shared_data, 'portlist', [])

            # Common ports to always check
            common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
            all_ports_to_scan = set(range(portstart, portend + 1))
            all_ports_to_scan.update(extra_ports)
            all_ports_to_scan.update(common_ports)

            open_ports = []
            lock = threading.Lock()
            semaphore = threading.Semaphore(100)  # Limit concurrent connections

            def scan_port(port):
                with semaphore:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(2)
                        result = s.connect_ex((ip, port))
                        s.close()
                        if result == 0:
                            with lock:
                                open_ports.append(port)
                                self.logger.info(f"Port {port} is open on {ip}")
                    except Exception:
                        pass

            # Start threads for port scanning
            threads = []
            self.logger.info(f"Scanning {len(all_ports_to_scan)} ports on {ip}...")

            for port in sorted(all_ports_to_scan):
                if self.shared_data.orchestrator_should_exit:
                    self.logger.info("Exit signal received, stopping port scan")
                    break
                t = threading.Thread(target=scan_port, args=(port,))
                t.start()
                threads.append(t)

            # Wait for all threads with timeout
            for t in threads:
                t.join(timeout=5)

            # Sort discovered ports
            open_ports.sort()
            self.logger.info(f"Found {len(open_ports)} open ports on {ip}: {open_ports}")

            # Update netkb file with discovered ports
            self._update_netkb_ports(ip, open_ports)

            duration = (datetime.now() - start_time).total_seconds()
            self.logger.info(f"[LIFECYCLE] PortScanner ENDED (success) for {ip} in {duration:.1f}s")
            return 'success'

        except Exception as e:
            self.logger.error(f"Error in port scan: {e}")
            self.logger.info(f"[LIFECYCLE] PortScanner ENDED (failed) for {ip}")
            return 'failed'

    def _update_netkb_ports(self, ip, open_ports):
        """Update the netkb CSV file with discovered ports for a specific IP."""
        try:
            netkb_file = self.shared_data.netkbfile
            if not os.path.exists(netkb_file):
                self.logger.error(f"netkb file not found: {netkb_file}")
                return

            # Read existing data
            rows = []
            headers = []
            with open(netkb_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                for row in reader:
                    rows.append(row)

            # Find and update the row for this IP
            updated = False
            for row in rows:
                if row.get('IPs') == ip:
                    # Merge existing ports with new ports
                    existing_ports = set()
                    if row.get('Ports'):
                        existing_ports = set(row['Ports'].split(';'))
                    new_ports = set(str(p) for p in open_ports)
                    all_ports = existing_ports.union(new_ports)
                    # Remove empty strings
                    all_ports.discard('')
                    # Sort numerically
                    sorted_ports = sorted(all_ports, key=lambda x: int(x) if x.isdigit() else 0)
                    row['Ports'] = ';'.join(sorted_ports)
                    updated = True
                    self.logger.info(f"Updated ports for {ip}: {row['Ports']}")
                    break

            if not updated:
                self.logger.warning(f"IP {ip} not found in netkb, cannot update ports")
                return

            # Write back
            with open(netkb_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)

        except Exception as e:
            self.logger.error(f"Error updating netkb ports: {e}")

    def mark_action_start(self, handler):
        """Mark the start time of the current action (server-side timestamp)."""
        try:
            # Store in shared_data so it persists across requests
            self.shared_data.action_start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.logger.info(f"Action start marked at {self.shared_data.action_start_time}")
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "start_time": self.shared_data.action_start_time}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def serve_logs(self, handler, current_action_only=False, since_timestamp=None):
        """
        Serve aggregated logs from all log files.
        If since_timestamp is provided, only return logs after that timestamp.
        If current_action_only is True, only return logs after the marked action start time.
        """
        try:
            import re
            logs_dir = self.shared_data.logsdir
            all_log_lines = []

            # Use server-tracked action start time if filtering for current action
            if current_action_only and hasattr(self.shared_data, 'action_start_time') and self.shared_data.action_start_time:
                since_timestamp = self.shared_data.action_start_time

            # Pattern to match valid log lines (start with timestamp, with optional milliseconds)
            timestamp_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?)')

            # Collect recent lines from all .log files in the logs directory
            if os.path.exists(logs_dir):
                for filename in os.listdir(logs_dir):
                    if filename.endswith('.log'):
                        log_path = os.path.join(logs_dir, filename)
                        try:
                            with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                                # Take last 200 lines from each file, filter valid log lines
                                for line in lines[-200:]:
                                    line = line.strip()
                                    match = timestamp_pattern.match(line)
                                    if match:
                                        log_ts = match.group(1)
                                        # Filter by since_timestamp if provided (use > not >= to avoid duplicates)
                                        if since_timestamp and log_ts <= since_timestamp:
                                            continue
                                        all_log_lines.append(line)
                        except Exception:
                            pass

            if not all_log_lines:
                handler.send_response(200)
                handler.send_header("Content-type", "text/plain")
                handler.end_headers()
                if since_timestamp:
                    handler.wfile.write(f"Waiting for logs...".encode('utf-8'))
                else:
                    handler.wfile.write(b"No log entries found yet. Run an attack to generate logs.")
                return

            # Sort by timestamp (including milliseconds)
            all_log_lines.sort(key=lambda x: x[:23])

            # Keep last 500 lines for display
            max_lines = 500
            if len(all_log_lines) > max_lines:
                all_log_lines = all_log_lines[-max_lines:]

            log_data = '\n'.join(all_log_lines)

            handler.send_response(200)
            handler.send_header("Content-type", "text/plain")
            handler.end_headers()
            handler.wfile.write(log_data.encode('utf-8'))
        except BrokenPipeError:
            pass
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def start_orchestrator(self, handler):
        try:
            self.shared_data.orchestrator_should_exit = False
            bjorn_instance = getattr(self.shared_data, 'bjorn_instance', None)
            if bjorn_instance is not None:
                bjorn_instance.start_orchestrator()
                message = "Orchestrator starting..."
            else:
                message = "Orchestrator flag set. Restart Bjorn to start orchestrator."
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": message}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def stop_orchestrator(self, handler):
        try:
            self.shared_data.orchestrator_should_exit = True
            bjorn_instance = getattr(self.shared_data, 'bjorn_instance', None)
            if bjorn_instance is not None:
                bjorn_instance.stop_orchestrator()
                message = "Orchestrator stopping..."
            else:
                message = "Orchestrator exit flag set."
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": message}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def backup(self, handler):
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"backup_{timestamp}.zip"
            backup_path = os.path.join(self.shared_data.backupdir, backup_filename)

            with zipfile.ZipFile(backup_path, 'w') as backup_zip:
                for folder in [self.shared_data.configdir, self.shared_data.datadir, self.shared_data.actions_dir, self.shared_data.resourcesdir]:
                    for root, dirs, files in os.walk(folder):
                        for file in files:
                            file_path = os.path.join(root, file)
                            backup_zip.write(file_path, os.path.relpath(file_path, self.shared_data.currentdir))

            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "url": f"/download_backup?filename={backup_filename}", "filename": backup_filename}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def restore(self, handler):
        try:
            content_length = int(handler.headers['Content-Length'])
            field_data = handler.rfile.read(content_length)
            field_storage = cgi.FieldStorage(fp=io.BytesIO(field_data), headers=handler.headers, environ={'REQUEST_METHOD': 'POST'})

            file_item = field_storage['file']
            if file_item.filename:
                backup_path = os.path.join(self.shared_data.upload_dir, file_item.filename)
                with open(backup_path, 'wb') as output_file:
                    output_file.write(file_item.file.read())

                with zipfile.ZipFile(backup_path, 'r') as backup_zip:
                    backup_zip.extractall(self.shared_data.currentdir)

                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "success", "message": "Restore completed successfully"}).encode('utf-8'))
            else:
                handler.send_response(400)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "error", "message": "No selected file"}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def download_backup(self, handler):
        query = unquote(handler.path.split('?filename=')[1])
        backup_path = os.path.join(self.shared_data.backupdir, query)
        if os.path.isfile(backup_path):
            handler.send_response(200)
            handler.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(backup_path)}"')
            handler.send_header("Content-type", "application/zip")
            handler.end_headers()
            with open(backup_path, 'rb') as file:
                handler.wfile.write(file.read())
        else:
            handler.send_response(404)
            handler.end_headers()

    def serve_credentials_data(self, handler):
        try:
            directory = self.shared_data.crackedpwddir
            html_content = self.generate_html_for_csv_files(directory)
            handler.send_response(200)
            handler.send_header("Content-type", "text/html")
            handler.end_headers()
            handler.wfile.write(html_content.encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def generate_html_for_csv_files(self, directory):
        # Define column width classes for consistent display
        column_classes = {
            'MAC Address': 'col-mac',
            'IP Address': 'col-ip',
            'Hostname': 'col-hostname',
            'User': 'col-user',
            'Password': 'col-password',
            'Port': 'col-port',
            'Share': 'col-share',
            'Database': 'col-database'
        }

        html = '<div class="credentials-container">\n'
        for filename in sorted(os.listdir(directory)):
            if filename.endswith('.csv'):
                filepath = os.path.join(directory, filename)
                # Get protocol name from filename (e.g., "ssh.csv" -> "SSH")
                protocol = filename.replace('.csv', '').upper()
                html += f'<h2>{protocol} Credentials</h2>\n'
                html += '<table class="styled-table cred-table">\n<thead>\n<tr>\n'
                with open(filepath, 'r') as file:
                    reader = csv.reader(file)
                    headers = next(reader)
                    for header in headers:
                        col_class = column_classes.get(header, '')
                        html += f'<th class="{col_class}">{header}</th>\n'
                    html += '</tr>\n</thead>\n<tbody>\n'
                    row_count = 0
                    for row in reader:
                        row_count += 1
                        html += '<tr>\n'
                        for idx, cell in enumerate(row):
                            col_class = column_classes.get(headers[idx], '') if idx < len(headers) else ''
                            html += f'<td class="{col_class}">{cell}</td>\n'
                        html += '</tr>\n'
                    if row_count == 0:
                        html += f'<tr><td colspan="{len(headers)}" class="no-data">No credentials found yet</td></tr>\n'
                html += '</tbody>\n</table>\n'
        html += '</div>\n'
        return html

    def list_files(self, directory):
        files = []
        for entry in os.scandir(directory):
            if entry.is_dir():
                files.append({
                    "name": entry.name,
                    "is_directory": True,
                    "children": self.list_files(entry.path)
                })
            else:
                files.append({
                    "name": entry.name,
                    "is_directory": False,
                    "path": entry.path
                })
        return files



    def serve_file(self, handler, filename):
        try:
            with open(os.path.join(self.shared_data.webdir, filename), 'r', encoding='utf-8') as file:
                content = file.read()
                content = content.replace('{{ web_delay }}', str(self.shared_data.web_delay * 1000))
                handler.send_response(200)
                handler.send_header("Content-type", "text/html")
                handler.end_headers()
                handler.wfile.write(content.encode('utf-8'))
        except FileNotFoundError:
            handler.send_response(404)
            handler.end_headers()

    def serve_current_config(self, handler):
        handler.send_response(200)
        handler.send_header("Content-type", "application/json")
        handler.end_headers()
        with open(self.shared_data.shared_config_json, 'r') as f:
            config = json.load(f)
        handler.wfile.write(json.dumps(config).encode('utf-8'))

    def restore_default_config(self, handler):
        handler.send_response(200)
        handler.send_header("Content-type", "application/json")
        handler.end_headers()
        self.shared_data.config = self.shared_data.default_config.copy()
        self.shared_data.save_config()
        handler.wfile.write(json.dumps(self.shared_data.config).encode('utf-8'))

    def serve_image(self, handler):
        image_path = os.path.join(self.shared_data.webdir, 'screen.png')
        try:
            with open(image_path, 'rb') as file:
                handler.send_response(200)
                handler.send_header("Content-type", "image/png")
                handler.send_header("Cache-Control", "max-age=0, must-revalidate")
                handler.end_headers()
                handler.wfile.write(file.read())
        except FileNotFoundError:
            handler.send_response(404)
            handler.end_headers()
        except BrokenPipeError:
            # Ignore broken pipe errors
            pass
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")


    def serve_favicon(self, handler):
        handler.send_response(200)
        handler.send_header("Content-type", "image/x-icon")
        handler.end_headers()
        favicon_path = os.path.join(self.shared_data.webdir, '/images/favicon.ico')
        self.logger.info(f"Serving favicon from {favicon_path}")
        try:
            with open(favicon_path, 'rb') as file:
                handler.wfile.write(file.read())
        except FileNotFoundError:
            self.logger.error(f"Favicon not found at {favicon_path}")
            handler.send_response(404)
            handler.end_headers()

    def serve_manifest(self, handler):
        handler.send_response(200)
        handler.send_header("Content-type", "application/json")
        handler.end_headers()
        manifest_path = os.path.join(self.shared_data.webdir, 'manifest.json')
        try:
            with open(manifest_path, 'r') as file:
                handler.wfile.write(file.read().encode('utf-8'))
        except FileNotFoundError:
            handler.send_response(404)
            handler.end_headers()
    
    def serve_apple_touch_icon(self, handler):
        handler.send_response(200)
        handler.send_header("Content-type", "image/png")
        handler.end_headers()
        icon_path = os.path.join(self.shared_data.webdir, 'icons/apple-touch-icon.png')
        try:
            with open(icon_path, 'rb') as file:
                handler.wfile.write(file.read())
        except FileNotFoundError:
            handler.send_response(404)
            handler.end_headers()

    def scan_wifi(self, handler):
        try:
            result = subprocess.Popen(['sudo', 'iwlist', 'wlan0', 'scan'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate()
            if result.returncode != 0:
                raise Exception(stderr)
            networks = self.parse_scan_result(stdout)
            self.logger.info(f"Found {len(networks)} networks")
            current_ssid = subprocess.Popen(['iwgetid', '-r'], stdout=subprocess.PIPE, text=True)
            ssid_out, ssid_err = current_ssid.communicate()
            if current_ssid.returncode != 0:
                raise Exception(ssid_err)
            current_ssid = ssid_out.strip()
            self.logger.info(f"Current SSID: {current_ssid}")
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"networks": networks, "current_ssid": current_ssid}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            self.logger.error(f"Error scanning Wi-Fi networks: {e}")
            handler.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))

    def parse_scan_result(self, scan_output):
        networks = []
        for line in scan_output.split('\n'):
            if 'ESSID' in line:
                ssid = line.split(':')[1].strip('"')
                if ssid not in networks:
                    networks.append(ssid)
        return networks

    def connect_wifi(self, handler):
        try:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length).decode('utf-8')
            params = json.loads(post_data)
            ssid = params['ssid']
            password = params['password']

            self.update_nmconnection(ssid, password)
            command = f'sudo nmcli connection up "preconfigured"'
            connect_result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = connect_result.communicate()
            if connect_result.returncode != 0:
                raise Exception(stderr)

            self.shared_data.wifichanged = True

            handler.send_response(200)
            handler.send_header('Content-type', 'application/json')
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "Connected to " + ssid}).encode('utf-8'))

        except Exception as e:
            handler.send_response(500)
            handler.send_header('Content-type', 'application/json')
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def disconnect_and_clear_wifi(self, handler):
        try:
            command_disconnect = 'sudo nmcli connection down "preconfigured"'
            disconnect_result = subprocess.Popen(command_disconnect, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = disconnect_result.communicate()
            if disconnect_result.returncode != 0:
                raise Exception(stderr)

            config_path = '/etc/NetworkManager/system-connections/preconfigured.nmconnection'
            with open(config_path, 'w') as f:
                f.write("")
            subprocess.Popen(['sudo', 'chmod', '600', config_path]).communicate()
            subprocess.Popen(['sudo', 'nmcli', 'connection', 'reload']).communicate()

            self.shared_data.wifichanged = False

            handler.send_response(200)
            handler.send_header('Content-type', 'application/json')
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "Disconnected from Wi-Fi and cleared preconfigured settings"}).encode('utf-8'))

        except Exception as e:
            handler.send_response(500)
            handler.send_header('Content-type', 'application/json')
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def clear_files(self, handler):
        try:
            # Clear logs, stolen data, scan results - but NOT credentials
            loot_dir = self.shared_data.loot_dir
            command = f"""
            rm -rf {loot_dir}/logs/* && rm -rf {loot_dir}/output/data_stolen/* && rm -rf {loot_dir}/output/scan_results/* && rm -rf {loot_dir}/output/vulnerabilities/* && rm -rf {loot_dir}/netkb.csv && rm -rf {loot_dir}/livestatus.csv && rm -rf {loot_dir}/archives/*
            """
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate()

            if result.returncode == 0:
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "success", "message": "Files cleared successfully"}).encode('utf-8'))
            else:
                handler.send_response(500)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "error", "message": stderr}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def clear_files_light(self, handler):
        try:
            # Light cleanup - only logs and scan results, NOT credentials or stolen data
            loot_dir = self.shared_data.loot_dir
            command = f"""
            rm -rf {loot_dir}/logs/* && rm -rf {loot_dir}/output/scan_results/* && rm -rf {loot_dir}/netkb.csv && rm -rf {loot_dir}/livestatus.csv
            """
            result = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = result.communicate()

            if result.returncode == 0:
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "success", "message": "Files cleared successfully"}).encode('utf-8'))
            else:
                handler.send_response(500)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "error", "message": stderr}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def clear_hosts(self, handler):
        """Clear the netkb file (discovered hosts) to start fresh on a new network."""
        try:
            netkb_file = self.shared_data.netkbfile
            # Recreate the file with just headers
            with open(netkb_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports'])

            self.logger.info(f"Cleared hosts from {netkb_file}")
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "Hosts cleared successfully. Run a network scan to discover new hosts."}).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error clearing hosts: {e}")
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def initialize_csv(self, handler):
        try:
            self.shared_data.generate_actions_json()
            self.shared_data.initialize_csv()
            self.shared_data.create_livestatusfile()
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "CSV files initialized successfully"}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def reboot_system(self, handler):
        try:
            command = "sudo reboot"
            subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "System is rebooting"}).encode('utf-8'))
        except subprocess.CalledProcessError as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def shutdown_system(self, handler):
        try:
            command = "sudo shutdown now"
            subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "System is shutting down"}).encode('utf-8'))
        except subprocess.CalledProcessError as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def restart_bjorn_service(self, handler):
        try:
            command = "sudo systemctl restart bjorn.service"
            subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "Bjorn service restarted successfully"}).encode('utf-8'))
        except subprocess.CalledProcessError as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def serve_network_data(self, handler):
        try:
            latest_file = max(
                [os.path.join(self.shared_data.scan_results_dir, f) for f in os.listdir(self.shared_data.scan_results_dir) if f.startswith('result_')],
                key=os.path.getctime
            )
            table_html = self.generate_html_table(latest_file)
            handler.send_response(200)
            handler.send_header("Content-type", "text/html")
            handler.end_headers()
            handler.wfile.write(table_html.encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def generate_html_table(self, file_path):
        table_html = '<table class="styled-table"><thead><tr>'
        with open(file_path, 'r') as file:
            reader = csv.reader(file)
            headers = next(reader)
            # First 4 columns are: IP, Hostname, Alive, MAC Address
            # Remaining columns are port numbers - consolidate into Open/Closed lists
            port_start_index = 4
            base_headers = headers[:port_start_index]
            port_headers = headers[port_start_index:]

            # Build new header row
            for header in base_headers:
                table_html += f'<th>{header}</th>'
            table_html += '<th>Open Ports</th><th>Closed Ports</th>'
            table_html += '</tr></thead><tbody>'

            for row in reader:
                table_html += '<tr>'
                # Display base columns (IP, Hostname, Alive, MAC)
                for idx, cell in enumerate(row[:port_start_index]):
                    cell_class = "green" if cell.strip() else "red"
                    table_html += f'<td class="{cell_class}">{cell}</td>'

                # Collect open and closed ports
                open_ports = []
                closed_ports = []
                for idx, cell in enumerate(row[port_start_index:]):
                    port_num = port_headers[idx] if idx < len(port_headers) else str(idx)
                    if cell.strip():
                        open_ports.append(port_num)
                    else:
                        closed_ports.append(port_num)

                # Display open ports column
                open_str = ', '.join(open_ports) if open_ports else 'none'
                table_html += f'<td class="green">{open_str}</td>'

                # Display closed ports column
                closed_str = ', '.join(closed_ports) if closed_ports else 'none'
                table_html += f'<td class="red">{closed_str}</td>'

                table_html += '</tr>'
            table_html += '</tbody></table>'
        return table_html

    def generate_html_table_netkb(self, file_path):
        """Generate a card-style HTML table for NetKB with collapsible rows per host."""
        html = ''
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                reader = csv.reader(file)
                headers = next(reader)

                # Create header index map
                h_idx = {h: i for i, h in enumerate(headers)}

                # Define column groups
                brute_force_cols = ['SSHBruteforce', 'FTPBruteforce', 'TelnetBruteforce',
                                   'SMBBruteforce', 'RDPBruteforce', 'SQLBruteforce']
                steal_cols = ['StealFilesSSH', 'StealFilesFTP', 'StealFilesTelnet',
                             'StealFilesSMB', 'StealFilesRDP', 'StealDataSQL']
                other_cols = ['NmapVulnScanner', 'NetworkScanner']

                def get_status(cell):
                    """Convert cell value to status indicator."""
                    if not cell or cell.strip() == '':
                        return '-', 'grey'
                    elif 'success' in cell.lower():
                        return '✓', 'green'
                    elif 'failed' in cell.lower():
                        return '✗', 'red'
                    else:
                        return cell[:10], ''  # Truncate long values

                def get_cell(row, col_name):
                    """Safely get cell value by column name."""
                    idx = h_idx.get(col_name, -1)
                    return row[idx] if idx >= 0 and idx < len(row) else ''

                # Count successes/failures for summary
                def count_status(row, cols):
                    success = 0
                    failed = 0
                    for col in cols:
                        val = get_cell(row, col)
                        if 'success' in val.lower():
                            success += 1
                        elif 'failed' in val.lower():
                            failed += 1
                    return success, failed

                card_id = 0
                for row in reader:
                    card_id += 1
                    mac = get_cell(row, 'MAC Address')
                    ips = get_cell(row, 'IPs')
                    hostnames = get_cell(row, 'Hostnames')
                    alive = get_cell(row, 'Alive')
                    ports = get_cell(row, 'Ports').replace(';', ', ')

                    alive_class = 'green' if alive == '1' else 'red'
                    alive_text = 'Yes' if alive == '1' else 'No'

                    # Count attack results for summary in header
                    bf_success, bf_failed = count_status(row, brute_force_cols)
                    st_success, st_failed = count_status(row, steal_cols)
                    total_success = bf_success + st_success
                    total_failed = bf_failed + st_failed

                    # Summary indicator
                    if total_success > 0:
                        summary = f'<span class="green">✓{total_success}</span>'
                    elif total_failed > 0:
                        summary = f'<span class="red">✗{total_failed}</span>'
                    else:
                        summary = '<span class="grey">-</span>'

                    # Host card with collapsible details
                    html += f'<div class="netkb-card" id="card-{card_id}">'

                    # Clickable header row
                    html += '<table class="styled-table netkb-table"><tbody>'
                    html += f'<tr class="host-header clickable" onclick="toggleCard({card_id})">'
                    html += f'<td colspan="2"><b>IP:</b> {ips}</td>'
                    html += f'<td colspan="2"><b>Host:</b> {hostnames if hostnames else "-"}</td>'
                    html += f'<td><b>Ports:</b> {ports if ports else "none"}</td>'
                    html += f'<td class="summary">{summary} <span class="toggle-icon" id="icon-{card_id}">▶</span></td>'
                    html += f'</tr>'

                    # Collapsible details (hidden by default)
                    html += f'<tr class="details" id="details-{card_id}" style="display:none;"><td colspan="6">'
                    html += '<table class="inner-table"><tbody>'

                    # MAC and Alive row
                    html += f'<tr>'
                    html += f'<td colspan="3"><b>MAC:</b> {mac if mac else "-"}</td>'
                    html += f'<td colspan="3" class="{alive_class}"><b>Alive:</b> {alive_text}</td>'
                    html += f'</tr>'

                    # Brute Force results
                    html += '<tr class="section-header"><td colspan="6"><b>Brute Force</b></td></tr>'
                    html += '<tr>'
                    for col in brute_force_cols:
                        status, css_class = get_status(get_cell(row, col))
                        label = col.replace('Bruteforce', '')
                        html += f'<td class="{css_class}" title="{get_cell(row, col)}">{label}: {status}</td>'
                    html += '</tr>'

                    # Steal Files results
                    html += '<tr class="section-header"><td colspan="6"><b>Data Theft</b></td></tr>'
                    html += '<tr>'
                    for col in steal_cols:
                        status, css_class = get_status(get_cell(row, col))
                        label = col.replace('StealFiles', '').replace('StealData', '')
                        html += f'<td class="{css_class}" title="{get_cell(row, col)}">{label}: {status}</td>'
                    html += '</tr>'

                    html += '</tbody></table>'
                    html += '</td></tr>'  # End details row
                    html += '</tbody></table>'
                    html += '</div>'  # End card

        except Exception as e:
            self.logger.error(f"Error in generate_html_table_netkb: {e}")
            html = f'<div class="error">Error loading NetKB: {e}</div>'
        return html


    def serve_netkb_data(self, handler):
        try:
            latest_file = self.shared_data.netkbfile
            table_html = self.generate_html_table_netkb(latest_file)
            handler.send_response(200)
            handler.send_header("Content-type", "text/html")
            handler.end_headers()
            handler.wfile.write(table_html.encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def update_nmconnection(self, ssid, password):
        config_path = '/etc/NetworkManager/system-connections/preconfigured.nmconnection'
        with open(config_path, 'w') as f:
            f.write(f"""
[connection]
id=preconfigured
uuid={uuid.uuid4()}
type=wifi
autoconnect=true

[wifi]
ssid={ssid}
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk={password}

[ipv4]
method=auto

[ipv6]
method=auto
""")
        subprocess.Popen(['sudo', 'chmod', '600', config_path]).communicate()
        subprocess.Popen(['sudo', 'nmcli', 'connection', 'reload']).communicate()

    def save_configuration(self, handler):
        try:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length).decode('utf-8')
            params = json.loads(post_data)
            fichier = self.shared_data.shared_config_json
            self.logger.info(f"Received params: {params}")

            with open(fichier, 'r') as f:
                current_config = json.load(f)

            for key, value in params.items():
                if isinstance(value, bool):
                    current_config[key] = value
                elif isinstance(value, str) and value.lower() in ['true', 'false']:
                    current_config[key] = value.lower() == 'true'
                elif isinstance(value, (int, float)):
                    current_config[key] = value
                elif isinstance(value, list):
                    # Lets boot any values in a list that are just empty strings
                    for val in value[:]:
                        if val == "" :
                            value.remove(val)
                    current_config[key] = value
                elif isinstance(value, str):
                    if value.replace('.', '', 1).isdigit():
                        current_config[key] = float(value) if '.' in value else int(value)
                    else:
                        current_config[key] = value
                else:
                    current_config[key] = value

            with open(fichier, 'w') as f:
                json.dump(current_config, f, indent=4)
            self.logger.info("Configuration saved to file")

            handler.send_response(200)
            handler.send_header('Content-type', 'application/json')
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "Configuration saved"}).encode('utf-8'))
            self.logger.info("Configuration saved (web)")

            self.shared_data.load_config()
            self.logger.info("Configuration reloaded (web)")

        except Exception as e:
            handler.send_response(500)
            handler.send_header('Content-type', 'application/json')
            handler.end_headers()
            error_message = {"status": "error", "message": str(e)}
            handler.wfile.write(json.dumps(error_message).encode('utf-8'))
            self.logger.error(f"Error saving configuration: {e}")

    def list_files(self, directory):
        files = []
        for entry in os.scandir(directory):
            if entry.is_dir():
                files.append({
                    "name": entry.name,
                    "is_directory": True,
                    "children": self.list_files(entry.path)
                })
            else:
                files.append({
                    "name": entry.name,
                    "is_directory": False,
                    "path": entry.path
                })
        return files

    def list_files_endpoint(self, handler):
        try:
            files = self.list_files(self.shared_data.datastolendir)
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps(files).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def download_file(self, handler):
        try:
            query = unquote(handler.path.split('?path=')[1])
            file_path = os.path.join(self.shared_data.datastolendir, query)
            if os.path.isfile(file_path):
                handler.send_response(200)
                handler.send_header("Content-Disposition", f'attachment; filename="{os.path.basename(file_path)}"')
                handler.end_headers()
                with open(file_path, 'rb') as file:
                    handler.wfile.write(file.read())
            else:
                handler.send_response(404)
                handler.end_headers()
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def list_logs_endpoint(self, handler):
        """List all log files organized by category."""
        try:
            # Define log categories
            categories = {
                "System": {
                    "logs": ["bjorn.py.log", "orchestrator.py.log", "webapp.py.log", "utils.py.log"],
                    "label": "System Logs"
                },
                "Scanning": {
                    "logs": ["scanning.py.log", "nmap_vuln_scanner.py.log"],
                    "label": "Network Scanning"
                },
                "SSH": {
                    "logs": ["ssh_connector.py.log", "steal_files_ssh.py.log"],
                    "label": "SSH (Brute Force + File Stealer)"
                },
                "FTP": {
                    "logs": ["ftp_connector.py.log", "steal_files_ftp.py.log"],
                    "label": "FTP (Brute Force + File Stealer)"
                },
                "SMB": {
                    "logs": ["smb_connector.py.log", "steal_files_smb.py.log"],
                    "label": "SMB (Brute Force + File Stealer)"
                },
                "Telnet": {
                    "logs": ["telnet_connector.py.log", "steal_files_telnet.py.log"],
                    "label": "Telnet (Brute Force + File Stealer)"
                },
                "RDP": {
                    "logs": ["rdp_connector.py.log", "steal_files_rdp.py.log"],
                    "label": "RDP (Brute Force + File Stealer)"
                },
                "SQL": {
                    "logs": ["sql_connector.py.log", "steal_data_sql.py.log"],
                    "label": "SQL (Brute Force + Data Stealer)"
                }
            }

            logs_dir = self.shared_data.logsdir
            result = {"categories": [], "uncategorized": []}
            found_logs = set()

            def get_log_info(filename):
                """Get log file info if it exists."""
                path = os.path.join(logs_dir, filename)
                if os.path.isfile(path):
                    size = os.path.getsize(path)
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size // 1024} KB"
                    else:
                        size_str = f"{size // (1024 * 1024)} MB"
                    return {"name": filename, "size": size_str, "path": filename}
                return None

            # Build categorized log list
            for cat_id, cat_info in categories.items():
                cat_logs = []
                for log_name in cat_info["logs"]:
                    log_info = get_log_info(log_name)
                    if log_info:
                        cat_logs.append(log_info)
                        found_logs.add(log_name)
                if cat_logs:
                    result["categories"].append({
                        "id": cat_id,
                        "label": cat_info["label"],
                        "logs": cat_logs
                    })

            # Find any uncategorized logs
            if os.path.exists(logs_dir):
                for entry in sorted(os.scandir(logs_dir), key=lambda e: e.name):
                    if entry.is_file() and entry.name.endswith('.log'):
                        if entry.name not in found_logs:
                            log_info = get_log_info(entry.name)
                            if log_info:
                                result["uncategorized"].append(log_info)

            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps(result).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def download_log(self, handler):
        """Download a specific log file."""
        try:
            query = unquote(handler.path.split('?name=')[1])
            # Sanitize - only allow filenames, no path traversal
            filename = os.path.basename(query)
            file_path = os.path.join(self.shared_data.logsdir, filename)
            if os.path.isfile(file_path):
                handler.send_response(200)
                handler.send_header("Content-Type", "text/plain; charset=utf-8")
                handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                handler.end_headers()
                with open(file_path, 'rb') as file:
                    handler.wfile.write(file.read())
            else:
                handler.send_response(404)
                handler.end_headers()
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))


