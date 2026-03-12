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
                        try:
                            prefix = self.shared_data.scan_network_prefix
                            network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                            networks.append({
                                'interface': current_iface,
                                'ip': ip,
                                'network': str(network),
                                'display': f"{ip}/{prefix} ({current_iface})"
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
                'RunAllAttacks': 'All Attacks',
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
                        # Include actions that have a specific port (not None, not 0) and aren't disabled
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

            # Build full host data for Network and Attacks tabs
            # Include MAC, hostname, alive, ports, and all action results per host
            action_columns = [
                'SSHBruteforce', 'FTPBruteforce', 'TelnetBruteforce',
                'SMBBruteforce', 'RDPBruteforce', 'SQLBruteforce',
                'StealFilesSSH', 'StealFilesFTP', 'StealFilesTelnet',
                'StealFilesSMB', 'StealDataSQL',
                'NmapVulnScanner'
            ]
            hosts = []
            for row in data:
                ip = row.get('IPs', row.get('IP Address', ''))
                actions_data = {}
                for col in action_columns:
                    val = row.get(col, '')
                    if val:
                        actions_data[col] = val
                hosts.append({
                    'mac': row.get('MAC Address', ''),
                    'ip': ip,
                    'hostname': row.get('Hostnames', ''),
                    'alive': row.get('Alive', ''),
                    'ports': row.get('Ports', ''),
                    'services': row.get('Services', ''),
                    'os': row.get('OS', ''),
                    'vendor': row.get('Vendor', ''),
                    'device_type': row.get('Device Type', ''),
                    'actions': actions_data
                })

            # Encode hostname in IP keys for vhost support (ip::hostname when hostname exists)
            def make_ip_key(row):
                ip = row.get('IPs', row.get('IP Address', ''))
                hostname = row.get('Hostnames', '')
                return f"{ip}::{hostname}" if hostname else ip

            response_data = {
                'ips': [make_ip_key(row) for row in data],
                'ports': {make_ip_key(row): get_ports_from_row(row) for row in data},
                'actions': valid_actions,
                'action_ports': action_ports,  # Map action -> port
                'port_to_actions': port_to_actions,  # Map port -> [actions] for auto-select
                'action_display_names': action_display_names,  # Friendly names
                'hosts': hosts  # Full host data for Network/Attacks tabs
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
            hostname = params.get('hostname', '')  # Optional: for vhost-aware HTTP scanning

            self.logger.info(f"Received request to execute {action_class} on {ip}:{port}")

            # Reject if an attack is already running
            if self.shared_data.manual_attack_running:
                raise Exception("An attack is already running. Stop it first.")

            # Orchestrator checks manual_mode in its loop and will stop.
            # No need to touch orchestrator_should_exit — worker threads use it to bail out.
            self.shared_data.manual_mode = True
            self.shared_data.orchestrator_should_exit = False

            # Track running attack so UI can recover state after browser refresh
            is_async = action_class in ('NetworkScanner', 'PortScanner', 'NmapVulnScanner', 'RunAllAttacks')
            self.shared_data.manual_attack_running = True
            self.shared_data.manual_attack_name = action_class

            # Set status so display shows the correct animation
            self.shared_data.lokiorch_status = action_class
            self.shared_data.lokistatustext2 = ip if ip else ""

            # Handle NetworkScanner specially - it scans the network, doesn't need an IP
            if action_class == 'NetworkScanner':
                self.ensure_network_scanner()  # Only load scanner module
                if network:
                    self.logger.info(f"Executing NetworkScanner on {network}...")
                else:
                    self.logger.info("Executing NetworkScanner to discover hosts...")
                import threading
                def run_network_scan():
                    try:
                        self.network_scanner.scan(network) if network else self.network_scanner.scan()
                    finally:
                        self.shared_data.lokiorch_status = "IDLE"
                        self.shared_data.lokistatustext2 = ""
                        self.shared_data.manual_attack_running = False
                        self.shared_data.manual_attack_name = None
                        self.shared_data.orchestrator_should_exit = False
                scan_thread = threading.Thread(target=run_network_scan)
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
                def run_port_scan():
                    try:
                        self.scan_ports_single_ip(ip)
                    finally:
                        self.shared_data.lokiorch_status = "IDLE"
                        self.shared_data.lokistatustext2 = ""
                        self.shared_data.manual_attack_running = False
                        self.shared_data.manual_attack_name = None
                        self.shared_data.orchestrator_should_exit = False
                scan_thread = threading.Thread(target=run_port_scan)
                scan_thread.start()
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "success", "message": f"Port scan started on {ip}"}).encode('utf-8'))
                return

            # Handle NmapVulnScanner - can run on specific IP or all hosts
            if action_class == 'NmapVulnScanner':
                self.ensure_nmap_scanner()  # Only load nmap module
                scan_hostname = hostname  # capture for closure
                scan_port = port  # capture specific port for closure (empty = all)
                self.logger.info(f"Executing NmapVulnScanner on {ip if ip else 'all hosts'}" + (f":{scan_port}" if scan_port else "") + (f" (Host: {scan_hostname})" if scan_hostname else "") + "...")
                import threading

                def run_vuln_scan():
                    try:
                        current_data = self.shared_data.read_data()
                        if ip:
                            # Match by IP+hostname for vhost targets
                            if scan_hostname:
                                row = next((r for r in current_data if r["IPs"] == ip and r.get("Hostnames", "") == scan_hostname), None)
                            else:
                                row = next((r for r in current_data if r["IPs"] == ip), None)
                            if row and row.get("Ports"):
                                # Pass a copy to execute() so we don't corrupt
                                # the real Ports column in netkb when restricting
                                scan_row = dict(row)
                                if scan_port:
                                    scan_row["Ports"] = scan_port
                                self.shared_data.attacksnbr += 1
                                result = self.nmap_vuln_scanner.execute(ip, scan_row, "NmapVulnScanner")
                                # Write back only the result column, not the modified Ports
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                row["NmapVulnScanner"] = f'{result}_{timestamp}'
                                self.shared_data.write_data(current_data)
                            else:
                                self.logger.warning(f"No data or ports found for IP: {ip}")
                        else:
                            for row in current_data:
                                if row.get("Alive") == "1" and row.get("Ports"):
                                    self.shared_data.attacksnbr += 1
                                    result = self.nmap_vuln_scanner.execute(row["IPs"], row, "NmapVulnScanner")
                                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                    row["NmapVulnScanner"] = f'{result}_{timestamp}'
                            self.shared_data.write_data(current_data)
                    except Exception as e:
                        self.logger.error(f"Error in vulnerability scan thread: {e}")
                    finally:
                        self.shared_data.lokiorch_status = "IDLE"
                        self.shared_data.lokistatustext2 = ""
                        self.shared_data.manual_attack_running = False
                        self.shared_data.manual_attack_name = None
                        self.shared_data.orchestrator_should_exit = False

                scan_thread = threading.Thread(target=run_vuln_scan)
                scan_thread.start()
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "success", "message": f"Vulnerability scan started{' on ' + ip if ip else ''}"}).encode('utf-8'))
                return

            # Handle RunAllAttacks - run all applicable attacks for a host based on open ports
            if action_class == 'RunAllAttacks':
                if not ip:
                    raise Exception("RunAllAttacks requires a target IP")
                run_all_hostname = hostname  # capture for closure
                self.logger.info(f"[LIFECYCLE] RunAllAttacks STARTED on {ip}")
                import threading

                def run_all_attacks():
                    try:
                        self._run_all_attacks(ip, run_all_hostname)
                    except Exception as e:
                        self.logger.error(f"Error in RunAllAttacks thread: {e}")
                    finally:
                        self.shared_data.lokiorch_status = "IDLE"
                        self.shared_data.lokistatustext2 = ""
                        self.shared_data.manual_attack_running = False
                        self.shared_data.manual_attack_name = None
                        self.shared_data.orchestrator_should_exit = False

                attack_thread = threading.Thread(target=run_all_attacks)
                attack_thread.start()
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"status": "success", "message": f"Running all attacks on {ip}"}).encode('utf-8'))
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
            self.shared_data.attacksnbr += 1
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
            self.shared_data.lokiorch_status = "IDLE"
            self.shared_data.lokistatustext2 = ""
            self.shared_data.manual_attack_running = False
            self.shared_data.manual_attack_name = None

            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "Manual attack executed"}).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error executing manual attack: {e}")
            self.shared_data.lokiorch_status = "IDLE"
            self.shared_data.lokistatustext2 = ""
            self.shared_data.manual_attack_running = False
            self.shared_data.manual_attack_name = None
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def _run_all_attacks(self, ip, hostname):
        """Run all applicable attacks on a host based on its open ports."""
        # Load actions config to know port mappings and parent relationships
        with open(self.shared_data.actions_file, 'r') as f:
            actions_config = json.load(f)

        # Build lookup tables from actions.json
        # action_info[b_class] = {b_port, b_parent, b_module}
        action_info = {}
        for action in actions_config:
            b_class = action.get('b_class')
            if b_class:
                action_info[b_class] = action

        # Read current host data to get open ports
        current_data = self.shared_data.read_data()
        if hostname:
            row = next((r for r in current_data if r["IPs"] == ip and r.get("Hostnames", "") == hostname), None)
        else:
            row = next((r for r in current_data if r["IPs"] == ip), None)

        if row is None:
            self.logger.error(f"[LIFECYCLE] RunAllAttacks: No data found for {ip}")
            self.logger.info(f"[LIFECYCLE] RunAllAttacks COMPLETE on {ip}: no host data")
            return

        ports_str = row.get('Ports', '')
        if not ports_str:
            self.logger.warning(f"[LIFECYCLE] RunAllAttacks: No open ports for {ip}")
            self.logger.info(f"[LIFECYCLE] RunAllAttacks COMPLETE on {ip}: no open ports")
            return

        # Parse ports
        open_ports = []
        for part in ports_str.replace(',', ';').split(';'):
            part = part.strip()
            if part and part.isdigit():
                open_ports.append(int(part))
        open_ports.sort()

        # Build ordered attack queue:
        # For each port: brute force first, then steal (only if brute succeeds)
        # Then NmapVulnScanner at the end
        attack_queue = []  # list of (action_class, port, parent_class_or_None)
        for port in open_ports:
            port_actions = [a for a in action_info.values()
                           if a.get('b_port') == port and a['b_class'] not in ('IDLE', 'NetworkScanner', 'NmapVulnScanner')]
            # Brute force actions (no parent)
            brute_actions = [a for a in port_actions if a.get('b_parent') is None]
            # Steal actions (have parent)
            steal_actions = [a for a in port_actions if a.get('b_parent') is not None]

            for ba in brute_actions:
                attack_queue.append((ba['b_class'], str(port), None))
            for sa in steal_actions:
                attack_queue.append((sa['b_class'], str(port), sa['b_parent']))

        # Append vuln scan at the end
        attack_queue.append(('NmapVulnScanner', '', None))

        total = len(attack_queue)
        self.logger.info(f"[LIFECYCLE] RunAllAttacks: {total} attacks queued for {ip} (ports: {open_ports})")

        results = {}  # action_class -> 'success' or 'failed'
        completed = 0

        for i, (action_class, port, parent_class) in enumerate(attack_queue, 1):
            # Check if we should stop
            if self.shared_data.orchestrator_should_exit:
                self.logger.info(f"[LIFECYCLE] RunAllAttacks: Stopped by user after {completed}/{total} attacks")
                break

            # Skip steal actions if their parent brute force failed
            if parent_class and results.get(parent_class) != 'success':
                self.logger.info(f"[LIFECYCLE] RunAllAttacks: Skipping {action_class} ({i}/{total}) — parent {parent_class} did not succeed")
                results[action_class] = 'skipped'
                completed += 1
                continue

            # Update UI status to show current sub-action
            self.shared_data.manual_attack_name = action_class

            port_display = f":{port}" if port else ""
            self.logger.info(f"[LIFECYCLE] RunAllAttacks: Running {action_class} on {ip}{port_display} ({i}/{total})")

            try:
                if action_class == 'NmapVulnScanner':
                    self.ensure_nmap_scanner()
                    # Re-read data fresh for vuln scan
                    current_data = self.shared_data.read_data()
                    if hostname:
                        row = next((r for r in current_data if r["IPs"] == ip and r.get("Hostnames", "") == hostname), None)
                    else:
                        row = next((r for r in current_data if r["IPs"] == ip), None)
                    if row and row.get("Ports"):
                        # Vuln scan uses all open ports from netkb (port 139
                        # dedup with 445 is handled inside the scanner itself)
                        self.shared_data.attacksnbr += 1
                        result = self.nmap_vuln_scanner.execute(ip, row, "NmapVulnScanner")
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        row["NmapVulnScanner"] = f'{result}_{timestamp}'
                        self.shared_data.write_data(current_data)
                        results[action_class] = result
                    else:
                        results[action_class] = 'skipped'
                else:
                    action_instance = self.ensure_single_action(action_class)
                    if action_instance is None:
                        self.logger.warning(f"[LIFECYCLE] RunAllAttacks: Action {action_class} not found, skipping")
                        results[action_class] = 'skipped'
                        completed += 1
                        continue

                    # Re-read data fresh for each action
                    current_data = self.shared_data.read_data()
                    if hostname:
                        row = next((r for r in current_data if r["IPs"] == ip and r.get("Hostnames", "") == hostname), None)
                    else:
                        row = next((r for r in current_data if r["IPs"] == ip), None)
                    if row is None:
                        results[action_class] = 'failed'
                        completed += 1
                        continue

                    action_key = action_instance.action_name
                    self.shared_data.attacksnbr += 1
                    result = action_instance.execute(ip, port, row, action_key)
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    row[action_key] = f'{result}_{timestamp}'
                    self.shared_data.write_data(current_data)
                    results[action_class] = result

            except Exception as e:
                self.logger.error(f"[LIFECYCLE] RunAllAttacks: {action_class} error: {e}")
                results[action_class] = 'failed'

            completed += 1

        # Log summary
        success_count = sum(1 for v in results.values() if v == 'success')
        failed_count = sum(1 for v in results.values() if v == 'failed')
        skipped_count = sum(1 for v in results.values() if v == 'skipped')
        self.logger.info(f"[LIFECYCLE] RunAllAttacks COMPLETE on {ip}: {success_count} succeeded, {failed_count} failed, {skipped_count} skipped out of {total}")

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
                    # Don't break — update all rows with same IP (vhost entries share ports)

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

    def stop_manual_attack(self, handler):
        """Stop a running manual attack by setting exit flag and killing subprocesses."""
        try:
            # Set exit flag to cause worker threads to stop
            self.shared_data.orchestrator_should_exit = True
            self.shared_data.manual_attack_running = False
            self.shared_data.manual_attack_name = None
            self.logger.info("Manual attack stop requested - exit flag set")
            # Kill any running nmap processes so the blocking subprocess.run() returns immediately
            try:
                subprocess.run(['killall', 'nmap'], capture_output=True, timeout=5)
                self.logger.info("Killed nmap processes")
            except Exception:
                pass
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "success", "message": "Attack stopping..."}).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

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

    def serve_host_loot_summary(self, handler, ip):
        """Return per-host loot counts: vulns, credentials, stolen_files."""
        try:
            # --- Vuln count ---
            vuln_count = 0
            vuln_dir = self.shared_data.vulnerabilities_dir
            if os.path.exists(vuln_dir):
                for fname in os.listdir(vuln_dir):
                    if fname.endswith('_vuln_details.json') and ip in fname:
                        try:
                            with open(os.path.join(vuln_dir, fname), 'r', encoding='utf-8') as f:
                                findings = json.load(f)
                            vuln_count = len(findings)
                        except Exception:
                            pass
                        break

            # --- Credential count ---
            cred_count = 0
            cred_dir = self.shared_data.crackedpwddir
            if os.path.exists(cred_dir):
                for fname in sorted(os.listdir(cred_dir)):
                    if not fname.endswith('.csv'):
                        continue
                    fpath = os.path.join(cred_dir, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8') as f:
                            for row in csv.DictReader(f):
                                if row.get('IP Address', '') == ip:
                                    cred_count += 1
                    except Exception:
                        pass

            # --- Stolen file count ---
            stolen_count = 0
            stolen_dir = self.shared_data.datastolendir
            if os.path.exists(stolen_dir):
                # Need MAC for directory prefix — look up from netkb
                mac = ''
                netkb = self.shared_data.netkbfile
                if os.path.exists(netkb):
                    try:
                        with open(netkb, 'r', encoding='utf-8') as f:
                            for row in csv.DictReader(f):
                                row_ip = row.get('IPs', row.get('IP Address', ''))
                                if row_ip == ip:
                                    mac = row.get('MAC Address', '')
                                    break
                    except Exception:
                        pass
                if mac:
                    dir_prefix = f'{mac}_{ip}'
                    for proto_name in ('ssh', 'ftp', 'smb', 'sql', 'telnet'):
                        proto_dir = os.path.join(stolen_dir, proto_name)
                        if not os.path.isdir(proto_dir):
                            continue
                        for dname in os.listdir(proto_dir):
                            if not dname.startswith(dir_prefix):
                                continue
                            host_dir = os.path.join(proto_dir, dname)
                            if not os.path.isdir(host_dir):
                                continue
                            for root, dirs, files in os.walk(host_dir):
                                stolen_count += len(files)

            result = {"vulns": vuln_count, "credentials": cred_count, "stolen_files": stolen_count}
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps(result).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error in host_loot_summary for {ip}: {e}")
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def serve_vulnerabilities(self, handler):
        """Serve vulnerability scan results as JSON."""
        try:
            summary_file = self.shared_data.vuln_summary_file
            vuln_dir = self.shared_data.vulnerabilities_dir
            summary = []

            if os.path.exists(summary_file):
                with open(summary_file, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        vulns = row.get("Vulnerabilities", "")
                        if vulns:
                            summary.append({
                                "ip": row.get("IP", ""),
                                "hostname": row.get("Hostname", ""),
                                "mac": row.get("MAC Address", ""),
                                "port": row.get("Port", ""),
                                "vulnerabilities": vulns
                            })

            # Count unique vulnerabilities
            all_vulns = set()
            for entry in summary:
                for v in entry["vulnerabilities"].split("; "):
                    if v.strip():
                        all_vulns.add(v.strip())

            # List available detail files and count KEV findings
            detail_files = []
            kev_count = 0
            if os.path.exists(vuln_dir):
                for f in os.listdir(vuln_dir):
                    if f.endswith('_vuln_scan.txt'):
                        detail_files.append(f)
                    elif f.endswith('_vuln_details.json'):
                        try:
                            with open(os.path.join(vuln_dir, f), 'r') as fh:
                                details = json.load(fh)
                            kev_count += sum(1 for d in details if d.get('kev'))
                        except Exception:
                            pass

            response = {
                "summary": summary,
                "total_count": len(all_vulns),
                "hosts_scanned": len(summary),
                "kev_count": kev_count,
                "detail_files": detail_files
            }

            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.send_header("Cache-Control", "no-cache")
            handler.end_headers()
            handler.wfile.write(json.dumps(response).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error serving vulnerabilities: {e}")
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def serve_vulnerability_detail(self, handler, ip):
        """Serve structured vulnerability details for a specific IP."""
        try:
            vuln_dir = self.shared_data.vulnerabilities_dir
            details = None

            if os.path.exists(vuln_dir):
                # Try JSON details first (structured data)
                for f in os.listdir(vuln_dir):
                    if f.endswith('_vuln_details.json') and ip in f:
                        file_path = os.path.join(vuln_dir, f)
                        with open(file_path, 'r', encoding='utf-8') as fh:
                            details = json.load(fh)
                        break

            if details is not None:
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"ip": ip, "findings": details, "scanned": True}).encode('utf-8'))
            else:
                # Return 200 with empty findings — no scan done yet
                handler.send_response(200)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"ip": ip, "findings": [], "scanned": False}).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error serving vulnerability detail: {e}")
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def update_kev_catalog(self, handler):
        """Download fresh CISA KEV catalog."""
        try:
            from cve_lookup import KevDatabase
            kev_path = os.path.join(self.shared_data.currentdir, 'data', 'kev_catalog.json')
            kev_db = KevDatabase(kev_path)
            success = kev_db.update()
            status_code = 200 if success else 500
            msg = f"KEV catalog updated: {kev_db.count} entries" if success else "Failed to update KEV catalog"
            handler.send_response(status_code)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "ok" if success else "error", "message": msg, "count": kev_db.count}).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error updating KEV catalog: {e}")
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def serve_stats(self, handler):
        """Serve dashboard stats from shared_data — zero computation, just reads attributes."""
        try:
            sd = self.shared_data
            stats = {
                'targetnbr': getattr(sd, 'targetnbr', 0),
                'portnbr': getattr(sd, 'portnbr', 0),
                'vulnnbr': getattr(sd, 'vulnnbr', 0),
                'crednbr': getattr(sd, 'crednbr', 0),
                'datanbr': getattr(sd, 'datanbr', 0),
                'zombiesnbr': getattr(sd, 'zombiesnbr', 0),
                'coinnbr': getattr(sd, 'coinnbr', 0),
                'levelnbr': getattr(sd, 'levelnbr', 0),
                'networkkbnbr': getattr(sd, 'networkkbnbr', 0),
                'attacksnbr': getattr(sd, 'attacksnbr', 0),
                'lokiorch_status': getattr(sd, 'lokiorch_status', 'IDLE'),
                'lokistatustext': getattr(sd, 'lokistatustext', 'IDLE'),
                'lokistatustext2': getattr(sd, 'lokistatustext2', ''),
                'manual_mode': getattr(sd, 'manual_mode', False),
                'manual_attack_running': getattr(sd, 'manual_attack_running', False),
                'manual_attack_name': getattr(sd, 'manual_attack_name', None),
                'orchestrator_should_exit': getattr(sd, 'orchestrator_should_exit', False),
                'web_title': getattr(sd, 'web_title', 'Loki'),
            }
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.send_header("Cache-Control", "no-cache")
            handler.end_headers()
            handler.wfile.write(json.dumps(stats).encode('utf-8'))
        except Exception as e:
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))

    def execute_terminal_command(self, handler):
        """Execute a command via subprocess and return output. Basic blocklist for dangerous patterns."""
        try:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length).decode('utf-8')
            params = json.loads(post_data)
            command = params.get('command', '').strip()

            if not command:
                handler.send_response(400)
                handler.send_header("Content-type", "application/json")
                handler.end_headers()
                handler.wfile.write(json.dumps({"error": "No command provided"}).encode('utf-8'))
                return

            # Block catastrophic commands
            blocked = ['rm -rf /', 'mkfs', 'dd if=/dev/zero', 'dd if=/dev/random',
                       '> /dev/sda', 'chmod -R 777 /', 'fork bomb']
            cmd_lower = command.lower()
            for pattern in blocked:
                if pattern in cmd_lower:
                    handler.send_response(403)
                    handler.send_header("Content-type", "application/json")
                    handler.end_headers()
                    handler.wfile.write(json.dumps({
                        "command": command, "output": "Command blocked for safety.", "exit_code": -1
                    }).encode('utf-8'))
                    return

            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30,
                cwd=self.shared_data.datadir
            )
            output = result.stdout
            if result.stderr:
                output += result.stderr

            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({
                "command": command,
                "output": output,
                "exit_code": result.returncode
            }).encode('utf-8'))
        except subprocess.TimeoutExpired:
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({
                "command": command,
                "output": "Command timed out (30s limit).",
                "exit_code": -1
            }).encode('utf-8'))
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

            # Deduplicate log lines (same message can appear in multiple log files)
            all_log_lines = list(dict.fromkeys(all_log_lines))

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
            self.shared_data.manual_mode = False
            self.shared_data.orchestrator_should_exit = False
            loki_instance = getattr(self.shared_data, 'loki_instance', None)
            if loki_instance is not None:
                loki_instance.start_orchestrator()
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
            loki_instance = getattr(self.shared_data, 'loki_instance', None)
            if loki_instance is not None:
                loki_instance.stop_orchestrator()
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
        # Merge saved config into default template order so web UI sections
        # are always correct (saved keys follow default key ordering)
        defaults = self.shared_data.get_default_config()
        with open(self.shared_data.shared_config_json, 'r') as f:
            saved = json.load(f)
        merged = {}
        for key in defaults:
            merged[key] = saved.get(key, defaults[key])
        # Append any extra keys from saved config not in defaults
        for key in saved:
            if key not in merged:
                merged[key] = saved[key]
        handler.wfile.write(json.dumps(merged).encode('utf-8'))

    def restore_default_config(self, handler):
        handler.send_response(200)
        handler.send_header("Content-type", "application/json")
        handler.end_headers()
        self.shared_data.config = self.shared_data.default_config.copy()
        self.shared_data.save_config()
        handler.wfile.write(json.dumps(self.shared_data.config).encode('utf-8'))

    def serve_image(self, handler):
        """Serve raw RGB565 framebuffer data for client-side rendering.

        Response body: 6-byte header followed by raw RGB565 pixel data.
        Header: uint16 LE fb_width (222) + uint16 LE fb_height (480) + uint16 LE rotation.
        The framebuffer memory layout is always 222x480 regardless of screen rotation.
        The client uses the rotation value to display the image correctly.
        """
        try:
            fb_path = '/dev/fb0'
            fb_width = 222
            fb_height = 480
            fb_size = fb_width * fb_height * 2  # RGB565 = 2 bytes/pixel
            rotation = getattr(self.shared_data, 'screen_rotation', 0)

            with open(fb_path, 'rb') as fb:
                raw = fb.read(fb_size)

            import struct
            header = struct.pack('<HHH', fb_width, fb_height, rotation)
            payload = header + raw

            handler.send_response(200)
            handler.send_header("Content-type", "application/octet-stream")
            handler.send_header("Content-Length", str(len(payload)))
            handler.send_header("Cache-Control", "no-cache, no-store")
            handler.end_headers()
            handler.wfile.write(payload)
        except FileNotFoundError:
            # No framebuffer (not on pager) - try static fallback
            image_path = os.path.join(self.shared_data.webdir, 'screen.png')
            try:
                with open(image_path, 'rb') as file:
                    data = file.read()
                    handler.send_response(200)
                    handler.send_header("Content-type", "image/png")
                    handler.end_headers()
                    handler.wfile.write(data)
            except FileNotFoundError:
                handler.send_response(404)
                handler.end_headers()
        except BrokenPipeError:
            pass
        except Exception as e:
            self.logger.error(f"Screenshot error: {e}")
            handler.send_response(500)
            handler.end_headers()


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

    def serve_theme(self, handler):
        """Serve the active theme's web palette as JSON."""
        theme_name = self.shared_data.config.get("theme", "bjorn")
        theme_dir = os.path.join(self.shared_data.currentdir, "themes", theme_name)
        theme_json_path = os.path.join(theme_dir, "theme.json")

        # Default web palette (bjorn/viking)
        web = {
            "bg_dark": "#1a1510",
            "bg_surface": "#231e17",
            "bg_elevated": "#2e261d",
            "accent": "#e99f00",
            "accent_bright": "#ffb829",
            "accent_dim": "#b87d00",
            "text_primary": "#e8e0d4",
            "text_secondary": "#9a8e7e",
            "text_muted": "#6b6156",
            "border": "#3a3226",
            "border_light": "#4a4236",
            "glow": "0 0 12px rgba(233, 159, 0, 0.25)",
            "font_title": "'Viking', 'Georgia', serif",
            "nav_label_display": "Display"
        }
        web_title = self.shared_data.web_title

        try:
            with open(theme_json_path, 'r') as f:
                theme_data = json.load(f)
            if "web" in theme_data:
                web = theme_data["web"]
            web_title = theme_data.get("web_title", web_title)
        except (FileNotFoundError, json.JSONDecodeError, IOError):
            pass

        response = json.dumps({
            "theme_name": theme_name,
            "web_title": web_title,
            "font_url": "/api/theme_font",
            "web": web
        })
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Cache-Control", "no-cache")
        handler.end_headers()
        handler.wfile.write(response.encode('utf-8'))

    def serve_theme_font(self, handler):
        """Serve the active theme's title font file."""
        theme_name = self.shared_data.config.get("theme", "bjorn")
        theme_dir = os.path.join(self.shared_data.currentdir, "themes", theme_name)

        # Try both .TTF and .ttf
        font_path = os.path.join(theme_dir, "fonts", "title.TTF")
        if not os.path.isfile(font_path):
            font_path = os.path.join(theme_dir, "fonts", "title.ttf")

        if os.path.isfile(font_path):
            handler.send_response(200)
            handler.send_header("Content-Type", "font/truetype")
            handler.send_header("Cache-Control", "public, max-age=3600")
            handler.end_headers()
            with open(font_path, 'rb') as f:
                handler.wfile.write(f.read())
        else:
            handler.send_response(404)
            handler.send_header("Content-Type", "application/json")
            handler.end_headers()
            handler.wfile.write(b'{"error": "Theme font not found"}')

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
            # Clear logs, stolen data, scan results, zombies - but NOT credentials
            loot_dir = self.shared_data.loot_dir
            command = f"""
            rm -rf {loot_dir}/logs/* && rm -rf {loot_dir}/output/data_stolen/* && rm -rf {loot_dir}/output/scan_results/* && rm -rf {loot_dir}/output/vulnerabilities/* && rm -rf {loot_dir}/output/zombies/* && rm -rf {loot_dir}/netkb.csv && rm -rf {loot_dir}/livestatus.csv && rm -rf {loot_dir}/archives/*
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

    def add_manual_target(self, handler):
        """Add a custom IP or hostname as a manual target in netkb."""
        import socket
        try:
            content_length = int(handler.headers['Content-Length'])
            post_data = handler.rfile.read(content_length).decode('utf-8')
            params = json.loads(post_data)
            target = params.get('target', '').strip()
            if not target:
                raise Exception("No target specified")

            # Resolve hostname to IP
            try:
                ip = socket.getaddrinfo(target, None, socket.AF_INET)[0][4][0]
            except socket.gaierror:
                raise Exception(f"Could not resolve: {target}")

            self.logger.info(f"Adding manual target: {target} -> {ip}")

            # Check if IP already exists in netkb
            netkb_file = self.shared_data.netkbfile
            rows = []
            headers = []
            if os.path.exists(netkb_file):
                with open(netkb_file, 'r', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    headers = reader.fieldnames or []
                    rows = list(reader)

            if not headers:
                headers = ['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports']

            hostname_val = target if target != ip else ''
            existing = next((r for r in rows if r.get('IPs') == ip and r.get('Hostnames', '') == hostname_val), None)
            if existing:
                existing['Alive'] = '1'
            else:
                new_row = {h: '' for h in headers}
                new_row['IPs'] = ip
                new_row['MAC Address'] = 'manual'
                new_row['Alive'] = '1'
                if target != ip:
                    new_row['Hostnames'] = target
                rows.append(new_row)

            with open(netkb_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)

            resp = {"status": "success", "ip": ip, "hostname": target if target != ip else ""}
            handler.send_response(200)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps(resp).encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error adding manual target: {e}")
            handler.send_response(400)
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

    def restart_loki_service(self, handler):
        try:
            command = "sudo systemctl restart loki.service"
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
                             'StealFilesSMB', 'StealDataSQL']
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
            self.logger.debug("Configuration saved to file")

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
                    "logs": ["Loki.py.log", "orchestrator.py.log", "webapp.py.log", "utils.py.log"],
                    "label": "System Logs"
                },
                "Scanning": {
                    "logs": ["scanning.py.log"],
                    "label": "Network Scanning"
                },
                "VulnScan": {
                    "logs": ["nmap_vuln_scanner.py.log"],
                    "label": "Vulnerability Scanner"
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
                    "logs": ["rdp_connector.py.log"],
                    "label": "RDP (Brute Force)"
                },
                "SQL": {
                    "logs": ["sql_bruteforce.py.log", "steal_data_sql.py.log"],
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

            # Add vuln scan result files from vulnerabilities directory
            vuln_dir = self.shared_data.vulnerabilities_dir
            if os.path.exists(vuln_dir):
                vuln_logs = []
                for entry in sorted(os.scandir(vuln_dir), key=lambda e: e.name):
                    if entry.is_file() and entry.name.endswith('_vuln_scan.txt'):
                        size = entry.stat().st_size
                        if size < 1024:
                            size_str = f"{size} B"
                        elif size < 1024 * 1024:
                            size_str = f"{size // 1024} KB"
                        else:
                            size_str = f"{size // (1024 * 1024)} MB"
                        vuln_logs.append({"name": entry.name, "size": size_str, "path": f"vuln:{entry.name}"})
                if vuln_logs:
                    result["categories"].append({
                        "id": "VulnResults",
                        "label": "Vulnerability Scan Results",
                        "logs": vuln_logs
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
            # Vuln result files use "vuln:" prefix to distinguish from log files
            if query.startswith('vuln:'):
                filename = os.path.basename(query[5:])
                file_path = os.path.join(self.shared_data.vulnerabilities_dir, filename)
            else:
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

    def export_host_report(self, handler, ip):
        """Generate and serve a plain-text intelligence report for a single host."""
        try:
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            lines = []
            W = 55  # ruler width

            lines.append('=' * W)
            lines.append(f' HOST REPORT: {ip}')
            lines.append(f' Generated: {now}')
            lines.append('=' * W)
            lines.append('')

            # --- Host info from netkb.csv ---
            host = {}
            netkb = self.shared_data.netkbfile
            if os.path.exists(netkb):
                with open(netkb, 'r', encoding='utf-8') as f:
                    for row in csv.DictReader(f):
                        row_ip = row.get('IPs', row.get('IP Address', ''))
                        if row_ip == ip:
                            host = row
                            break

            lines.append(f'--- HOST INFO {"-" * (W - 14)}')
            lines.append(f'{"IP:":<13}{ip}')
            lines.append(f'{"Hostname:":<13}{host.get("Hostnames", "")}')
            lines.append(f'{"MAC:":<13}{host.get("MAC Address", "")}')
            lines.append(f'{"Vendor:":<13}{host.get("Vendor", "")}')
            lines.append(f'{"Device Type:":<13}{host.get("Device Type", "")}')
            lines.append(f'{"OS:":<13}{host.get("OS", "")}')
            lines.append(f'{"Status:":<13}{"ALIVE" if host.get("Alive") == "1" else "DOWN"}')
            lines.append('')

            # --- Open ports & services ---
            services_str = host.get('Services', '')
            if services_str:
                parts = [s.strip() for s in services_str.split(';') if s.strip()]
                valid = []
                for part in parts:
                    sp = part.split(':', 1)
                    port_num = sp[0].strip()
                    if port_num and port_num.isdigit():
                        svc_info = sp[1] if len(sp) > 1 else ''
                        slash_idx = svc_info.find('/')
                        if slash_idx != -1:
                            svc_name = svc_info[:slash_idx]
                            version = svc_info[slash_idx + 1:]
                        else:
                            svc_name = svc_info
                            version = ''
                        valid.append((f'{port_num}/tcp', svc_name, version))
                if valid:
                    lines.append(f'--- OPEN PORTS & SERVICES {"-" * (W - 25)}')
                    lines.append(f'{"PORT":<10}{"SERVICE":<17}VERSION')
                    for p, s, v in valid:
                        lines.append(f'{p:<10}{s:<17}{v}')
                    lines.append('')

            # --- Credentials ---
            cred_dir = self.shared_data.crackedpwddir
            cred_lines = []
            if os.path.exists(cred_dir):
                for fname in sorted(os.listdir(cred_dir)):
                    if not fname.endswith('.csv'):
                        continue
                    proto = fname.replace('.csv', '').upper()
                    fpath = os.path.join(cred_dir, fname)
                    try:
                        with open(fpath, 'r', encoding='utf-8') as f:
                            for row in csv.DictReader(f):
                                if row.get('IP Address', '') == ip:
                                    user = row.get('User', '')
                                    pw = row.get('Password', '')
                                    port = row.get('Port', '')
                                    extra = ''
                                    if row.get('Share'):
                                        extra = f', share: {row["Share"]}'
                                    if row.get('Database'):
                                        extra = f', db: {row["Database"]}'
                                    cred_lines.append(f'[{proto}] {user}:{pw} (port {port}{extra})')
                    except Exception:
                        pass
            if cred_lines:
                lines.append(f'--- CREDENTIALS {"-" * (W - 16)}')
                lines.extend(cred_lines)
                lines.append('')

            # --- Vulnerabilities ---
            vuln_dir = self.shared_data.vulnerabilities_dir
            vuln_lines = []
            if os.path.exists(vuln_dir):
                for fname in os.listdir(vuln_dir):
                    if fname.endswith('_vuln_details.json') and ip in fname:
                        try:
                            with open(os.path.join(vuln_dir, fname), 'r', encoding='utf-8') as f:
                                findings = json.load(f)
                            for f_item in findings:
                                severity = 'INFO'
                                cvss = f_item.get('cvss_score')
                                if cvss is not None:
                                    if cvss >= 9.0:
                                        severity = 'CRITICAL'
                                    elif cvss >= 7.0:
                                        severity = 'HIGH'
                                    elif cvss >= 4.0:
                                        severity = 'MEDIUM'
                                    else:
                                        severity = 'LOW'
                                cves = ', '.join(f_item.get('cves', []))
                                title = f_item.get('title', 'Unknown')
                                cvss_str = f' (CVSS {cvss})' if cvss is not None else ''
                                vuln_lines.append(f'[{severity}] {cves + " — " if cves else ""}{title}{cvss_str}')
                                if f_item.get('port'):
                                    svc = f' ({f_item["service"]})' if f_item.get('service') else ''
                                    vuln_lines.append(f'  Port: {f_item["port"]}{svc}')
                                state = f_item.get('state', '')
                                if state:
                                    vuln_lines.append(f'  State: {state}')
                                if f_item.get('kev'):
                                    vuln_lines.append('  CISA KEV: Yes — Known Exploited')
                                if f_item.get('ransomware_use') == 'Known':
                                    vuln_lines.append('  Ransomware: Known Use')
                                desc = f_item.get('description', '')
                                if desc:
                                    vuln_lines.append(f'  {desc[:200]}')
                                vuln_lines.append('')
                        except Exception:
                            pass
                        break
            if vuln_lines:
                lines.append(f'--- VULNERABILITIES {"-" * (W - 20)}')
                lines.extend(vuln_lines)

            # --- Attack results ---
            action_columns = [
                'SSHBruteforce', 'FTPBruteforce', 'TelnetBruteforce',
                'SMBBruteforce', 'RDPBruteforce', 'SQLBruteforce',
                'StealFilesSSH', 'StealFilesFTP', 'StealFilesTelnet',
                'StealFilesSMB', 'StealDataSQL', 'NmapVulnScanner'
            ]
            attack_lines = []
            for col in action_columns:
                val = host.get(col, '')
                if val:
                    attack_lines.append(f'{col + ":":<22}{val}')
            if attack_lines:
                lines.append(f'--- ATTACK RESULTS {"-" * (W - 19)}')
                lines.extend(attack_lines)
                lines.append('')

            # --- Stolen files ---
            stolen_dir = self.shared_data.datastolendir
            stolen_lines = []
            mac = host.get('MAC Address', '')
            if os.path.exists(stolen_dir) and mac:
                dir_prefix = f'{mac}_{ip}'
                for proto_name in ('ssh', 'ftp', 'smb', 'sql', 'telnet'):
                    proto_dir = os.path.join(stolen_dir, proto_name)
                    if not os.path.isdir(proto_dir):
                        continue
                    for dname in os.listdir(proto_dir):
                        if not dname.startswith(dir_prefix):
                            continue
                        host_dir = os.path.join(proto_dir, dname)
                        if not os.path.isdir(host_dir):
                            continue
                        for root, dirs, files in os.walk(host_dir):
                            for fname in files:
                                rel = os.path.relpath(os.path.join(root, fname), host_dir)
                                stolen_lines.append(f'[{proto_name.upper()}] {rel}')
            if stolen_lines:
                lines.append(f'--- STOLEN FILES {"-" * (W - 17)}')
                lines.extend(stolen_lines)
                lines.append('')

            report = '\n'.join(lines)
            report_bytes = report.encode('utf-8')
            safe_ip = ip.replace(':', '_')  # handle IPv6 if ever
            handler.send_response(200)
            handler.send_header("Content-Type", "text/plain; charset=utf-8")
            handler.send_header("Content-Disposition", f'attachment; filename="host_report_{safe_ip}.txt"')
            handler.send_header("Content-Length", str(len(report_bytes)))
            handler.end_headers()
            handler.wfile.write(report_bytes)
        except Exception as e:
            self.logger.error(f"Error exporting host report for {ip}: {e}")
            handler.send_response(500)
            handler.send_header("Content-type", "application/json")
            handler.end_headers()
            handler.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode('utf-8'))


