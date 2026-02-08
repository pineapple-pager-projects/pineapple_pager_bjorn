#scanning.py
# This script performs a network scan to identify live hosts, their MAC addresses, and open ports.
# Modified for Pager: removed pandas/rich dependencies, using csv module instead.

import os
import threading
import csv
import socket
import subprocess
import time
import glob
import logging
from datetime import datetime
from getmac import get_mac_address as gma
from shared import SharedData
from logger import Logger
from timeout_utils import join_threads_with_timeout
import ipaddress
import nmap

logger = Logger(name="scanning.py", level=logging.INFO)

b_class = "NetworkScanner"
b_module = "scanning"
b_status = "network_scanner"
b_port = None
b_parent = None
b_priority = 1

class NetworkScanner:
    """
    This class handles the entire network scanning process.
    """
    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.logger = logger
        self.displaying_csv = shared_data.displaying_csv
        self.blacklistcheck = shared_data.blacklistcheck
        self.mac_scan_blacklist = shared_data.mac_scan_blacklist
        self.ip_scan_blacklist = shared_data.ip_scan_blacklist
        self.lock = threading.Lock()
        self.currentdir = shared_data.currentdir
        self.semaphore = threading.Semaphore(200)
        self.nm = nmap.PortScanner()
        self.running = False

    def check_if_csv_scan_file_exists(self, csv_scan_file, csv_result_file, netkbfile):
        """
        Checks and prepares the necessary CSV files for the scan.
        """
        with self.lock:
            try:
                if not os.path.exists(os.path.dirname(csv_scan_file)):
                    os.makedirs(os.path.dirname(csv_scan_file))
                if not os.path.exists(os.path.dirname(netkbfile)):
                    os.makedirs(os.path.dirname(netkbfile))
                if os.path.exists(csv_scan_file):
                    os.remove(csv_scan_file)
                if os.path.exists(csv_result_file):
                    os.remove(csv_result_file)
                if not os.path.exists(netkbfile):
                    with open(netkbfile, 'w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports'])
            except Exception as e:
                self.logger.error(f"Error in check_if_csv_scan_file_exists: {e}")

    def get_current_timestamp(self):
        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def ip_key(self, ip):
        if ip == "STANDALONE":
            return (0, 0, 0, 0)
        try:
            return tuple(map(int, ip.split('.')))
        except ValueError as e:
            self.logger.error(f"Error in ip_key: {e}")
            return (0, 0, 0, 0)

    def sort_and_write_csv(self, csv_scan_file):
        with self.lock:
            try:
                with open(csv_scan_file, 'r') as file:
                    lines = file.readlines()
                sorted_lines = [lines[0]] + sorted(lines[1:], key=lambda x: self.ip_key(x.split(',')[0]))
                with open(csv_scan_file, 'w') as file:
                    file.writelines(sorted_lines)
            except Exception as e:
                self.logger.error(f"Error in sort_and_write_csv: {e}")

    class GetIpFromCsv:
        def __init__(self, outer_instance, csv_scan_file):
            self.outer_instance = outer_instance
            self.csv_scan_file = csv_scan_file
            self.ip_list = []
            self.hostname_list = []
            self.mac_list = []
            self.get_ip_from_csv()

        def get_ip_from_csv(self):
            with self.outer_instance.lock:
                try:
                    with open(self.csv_scan_file, 'r') as csv_scan_file:
                        csv_reader = csv.reader(csv_scan_file)
                        next(csv_reader)
                        for row in csv_reader:
                            if row[0] == "STANDALONE" or row[1] == "STANDALONE" or row[2] == "STANDALONE":
                                continue
                            if not self.outer_instance.blacklistcheck or (row[2] not in self.outer_instance.mac_scan_blacklist and row[0] not in self.outer_instance.ip_scan_blacklist):
                                self.ip_list.append(row[0])
                                self.hostname_list.append(row[1])
                                self.mac_list.append(row[2])
                except Exception as e:
                    self.outer_instance.logger.error(f"Error in get_ip_from_csv: {e}")

    def ping_host(self, ip):
        """Simple ICMP ping check - returns True if host responds."""
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip],
                capture_output=True,
                timeout=3
            )
            return result.returncode == 0
        except Exception:
            return False

    def update_netkb(self, netkbfile, netkb_data, alive_macs, scanned_network=None):
        with self.lock:
            try:
                netkb_entries = {}
                existing_action_columns = []
                existing_headers = ['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports']

                if os.path.exists(netkbfile):
                    with open(netkbfile, 'r') as file:
                        reader = csv.DictReader(file)
                        existing_headers = reader.fieldnames
                        existing_action_columns = [header for header in existing_headers if header not in ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"]]
                        for row in reader:
                            mac = row["MAC Address"]
                            ips = row["IPs"].split(';')
                            hostnames = row["Hostnames"].split(';')
                            alive = row["Alive"]
                            ports = row["Ports"].split(';')
                            # Filter out hostnames that are just IP addresses
                            ip_set = set(ips) if ips[0] else set()
                            valid_hostnames = set(h for h in hostnames if h and h not in ip_set)
                            netkb_entries[mac] = {
                                'IPs': ip_set,
                                'Hostnames': valid_hostnames,
                                'Alive': alive,
                                'Ports': set(ports) if ports[0] else set()
                            }
                            for action in existing_action_columns:
                                netkb_entries[mac][action] = row.get(action, "")

                # Ping fallback: check existing hosts not detected by nmap
                # Only check hosts within the scanned network range
                for mac, data in netkb_entries.items():
                    if mac not in alive_macs and mac != "STANDALONE":
                        for ip in data['IPs']:
                            # Skip blacklisted IPs (including this device)
                            if self.blacklistcheck and ip in self.ip_scan_blacklist:
                                continue
                            # Skip IPs not in the scanned network range
                            if scanned_network:
                                try:
                                    if ipaddress.IPv4Address(ip) not in scanned_network:
                                        continue
                                except:
                                    continue
                            if self.ping_host(ip):
                                self.logger.info(f"Ping fallback: {ip} ({mac}) is alive")
                                alive_macs.add(mac)
                                break

                ip_to_mac = {}

                for data in netkb_data:
                    mac, ip, hostname, ports = data
                    if not mac or mac == "STANDALONE" or ip == "STANDALONE" or hostname == "STANDALONE":
                        continue
                    if mac == "00:00:00:00:00:00":
                        continue
                    if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                        continue

                    if ip in ip_to_mac and ip_to_mac[ip] != mac:
                        old_mac = ip_to_mac[ip]
                        if old_mac in netkb_entries:
                            netkb_entries[old_mac]['Alive'] = '0'

                    ip_to_mac[ip] = mac
                    if mac in netkb_entries:
                        netkb_entries[mac]['IPs'].add(ip)
                        # Only add hostname if it's not the IP address
                        if hostname and hostname != ip:
                            netkb_entries[mac]['Hostnames'].add(hostname)
                        netkb_entries[mac]['Alive'] = '1'
                        netkb_entries[mac]['Ports'].update(map(str, ports))
                    else:
                        netkb_entries[mac] = {
                            'IPs': {ip},
                            'Hostnames': {hostname} if hostname and hostname != ip else set(),
                            'Alive': '1',
                            'Ports': set(map(str, ports))
                        }
                        for action in existing_action_columns:
                            netkb_entries[mac][action] = ""

                for mac in netkb_entries:
                    if mac not in alive_macs:
                        netkb_entries[mac]['Alive'] = '0'

                netkb_entries = {mac: data for mac, data in netkb_entries.items() if len(data['IPs']) == 1}
                sorted_netkb_entries = sorted(netkb_entries.items(), key=lambda x: self.ip_key(sorted(x[1]['IPs'])[0]))

                with open(netkbfile, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(existing_headers)
                    for mac, data in sorted_netkb_entries:
                        row = [
                            mac,
                            ';'.join(sorted(data['IPs'], key=self.ip_key)),
                            ';'.join(sorted(data['Hostnames'])),
                            data['Alive'],
                            ';'.join(sorted(data['Ports'], key=lambda x: int(x) if x else 0))
                        ]
                        row.extend(data.get(action, "") for action in existing_action_columns)
                        writer.writerow(row)
            except Exception as e:
                self.logger.error(f"Error in update_netkb: {e}")

    def display_csv(self, file_path):
        """Display CSV contents via logger instead of rich."""
        with self.lock:
            try:
                with open(file_path, 'r') as file:
                    reader = csv.reader(file)
                    headers = next(reader)
                    self.logger.info(f"CSV: {file_path}")
                    self.logger.info(f"Headers: {', '.join(headers)}")
                    for row in reader:
                        self.logger.info(f"  {', '.join(row)}")
            except Exception as e:
                self.logger.error(f"Error in display_csv: {e}")

    def get_network(self):
        """Get network info using ip commands (Pager compatible, no netifaces needed)."""
        try:
            # Get configured scan prefix (default /24 if not set)
            scan_prefix = getattr(self.shared_data, 'scan_network_prefix', 24)
            if scan_prefix is None:
                scan_prefix = 24

            # Check if interface was pre-selected via environment variable (from payload.sh)
            env_interface = os.environ.get('BJORN_INTERFACE')
            env_ip = os.environ.get('BJORN_IP')

            if env_interface and env_ip:
                # Use pre-selected interface from payload.sh
                self.logger.info(f"Using pre-selected interface: {env_interface} ({env_ip})")
                ip_addr = ipaddress.IPv4Address(env_ip)
                network = ipaddress.IPv4Network(f"{ip_addr}/{scan_prefix}", strict=False)
                self.logger.info(f"Network: {network} (prefix /{scan_prefix} from config)")
                return network

            # Auto-detect: Get default route interface and gateway
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                    capture_output=True, text=True, timeout=5)
            if not result.stdout.strip():
                self.logger.error("No default route found")
                return None

            # Parse: "default via 192.168.1.1 dev wlan0"
            parts = result.stdout.strip().split()
            if 'via' in parts and 'dev' in parts:
                dev_idx = parts.index('dev')
                iface_name = parts[dev_idx + 1]
            else:
                self.logger.error("Could not parse default route")
                return None

            # Get IP address and prefix length for that interface
            result = subprocess.run(['ip', '-o', '-4', 'addr', 'show', iface_name],
                                    capture_output=True, text=True, timeout=5)
            if not result.stdout.strip():
                self.logger.error(f"No IP address on {iface_name}")
                return None

            # Parse: "2: wlan0    inet 192.168.1.100/24 brd 192.168.1.255 scope global wlan0"
            for line in result.stdout.strip().split('\n'):
                if 'inet ' in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == 'inet' and i + 1 < len(parts):
                            ip_cidr = parts[i + 1]  # e.g., "192.168.1.100/24"
                            # Get the IP address
                            ip_addr = ipaddress.IPv4Address(ip_cidr.split('/')[0])
                            # Apply configured prefix (use larger prefix = smaller network)
                            network = ipaddress.IPv4Network(f"{ip_addr}/{scan_prefix}", strict=False)
                            self.logger.info(f"Network: {network} (prefix /{scan_prefix} from config)")
                            return network

            self.logger.error("Could not parse IP address")
            return None
        except Exception as e:
            self.logger.error(f"Error in get_network: {e}")
            return None

    def get_hostname_netbios(self, ip):
        """Get hostname using NetBIOS name query (works for Windows/Samba devices)."""
        try:
            result = subprocess.run(
                ['nmblookup', '-A', ip],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Parse output for hostname (first name entry, not workgroup)
                for line in result.stdout.splitlines():
                    line = line.strip()
                    # Lines look like: "HOSTNAME        <00> -         B <ACTIVE>"
                    if '<00>' in line and '<GROUP>' not in line:
                        parts = line.split()
                        if parts:
                            hostname = parts[0]
                            if hostname and hostname != ip:
                                return hostname
        except FileNotFoundError:
            # nmblookup not installed
            pass
        except Exception as e:
            self.logger.debug(f"NetBIOS lookup failed for {ip}: {e}")
        return ""

    def get_hostname_mdns(self, ip):
        """Get hostname using mDNS/Avahi (works for Apple/Linux devices)."""
        try:
            result = subprocess.run(
                ['avahi-resolve', '-a', ip],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and result.stdout.strip():
                # Output: "192.168.1.100    hostname.local"
                parts = result.stdout.strip().split()
                if len(parts) >= 2:
                    hostname = parts[1]
                    # Remove .local suffix if present
                    if hostname.endswith('.local'):
                        hostname = hostname[:-6]
                    if hostname and hostname != ip:
                        return hostname
        except FileNotFoundError:
            # avahi-resolve not installed
            pass
        except Exception as e:
            self.logger.debug(f"mDNS lookup failed for {ip}: {e}")
        return ""

    def get_hostname_nmap(self, ip):
        """Get hostname using nmap with hostname resolution."""
        try:
            # Quick nmap scan with hostname resolution
            result = subprocess.run(
                ['nmap', '-sn', '-R', '--system-dns', ip],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # Parse output for hostname
                for line in result.stdout.splitlines():
                    if 'Nmap scan report for' in line:
                        # Format: "Nmap scan report for hostname (IP)" or just "Nmap scan report for IP"
                        parts = line.replace('Nmap scan report for ', '').strip()
                        if '(' in parts:
                            hostname = parts.split('(')[0].strip()
                            if hostname and hostname != ip:
                                return hostname
        except Exception as e:
            self.logger.debug(f"Nmap hostname lookup failed for {ip}: {e}")
        return ""

    def get_hostname(self, ip):
        """Get hostname for IP using multiple methods."""
        # Try reverse DNS first (fastest if available)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            if hostname and hostname != ip:
                return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        except Exception as e:
            self.logger.debug(f"Reverse DNS failed for {ip}: {e}")

        # Try NetBIOS (Windows/Samba devices)
        hostname = self.get_hostname_netbios(ip)
        if hostname:
            return hostname

        # Try mDNS/Avahi (Apple/Linux devices)
        hostname = self.get_hostname_mdns(ip)
        if hostname:
            return hostname

        # Try nmap with DNS resolution as last resort
        hostname = self.get_hostname_nmap(ip)
        if hostname:
            return hostname

        return ""

    def get_mac_address(self, ip, hostname):
        try:
            mac = None
            retries = 3  # Reduced retries for faster scanning

            # First try without ping
            mac = gma(ip=ip)

            # If no MAC, ping to populate ARP cache then retry
            if not mac:
                try:
                    # Quick ping to populate ARP cache
                    subprocess.run(
                        ['ping', '-c', '1', '-W', '1', ip],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=2
                    )
                    time.sleep(0.5)  # Give ARP cache time to update
                except Exception:
                    pass

                # Retry MAC lookup after ping
                while not mac and retries > 0:
                    mac = gma(ip=ip)
                    if not mac:
                        time.sleep(0.5)
                        retries -= 1

            if not mac:
                # MAC lookup failed (host may be on different subnet/VLAN)
                self.logger.debug(f"Could not get MAC for {ip} (may be on different subnet)")
                return ""
            return mac
        except Exception as e:
            self.logger.error(f"Error in get_mac_address: {e}")
            return ""

    class PortScanner:
        def __init__(self, outer_instance, target, open_ports, portstart, portend, extra_ports):
            self.outer_instance = outer_instance
            self.logger = logger
            self.target = target
            self.open_ports = open_ports
            self.portstart = portstart
            self.portend = portend
            self.extra_ports = extra_ports

        def scan(self, port):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                con = s.connect((self.target, port))
                self.open_ports[self.target].append(port)
                con.close()
            except:
                pass
            finally:
                s.close()

        def start(self):
            try:
                for port in range(self.portstart, self.portend):
                    t = threading.Thread(target=self.scan_with_semaphore, args=(port,))
                    t.start()
                for port in self.extra_ports:
                    t = threading.Thread(target=self.scan_with_semaphore, args=(port,))
                    t.start()
            except Exception as e:
                self.logger.info(f"Maximum threads defined in the semaphore reached: {e}")

        def scan_with_semaphore(self, port):
            with self.outer_instance.semaphore:
                self.scan(port)

    class ScanPorts:
        def __init__(self, outer_instance, network, portstart, portend, extra_ports):
            self.outer_instance = outer_instance
            self.logger = logger
            self.progress = 0
            self.network = network
            self.portstart = portstart
            self.portend = portend
            self.extra_ports = extra_ports
            self.currentdir = outer_instance.currentdir
            self.scan_results_dir = outer_instance.shared_data.scan_results_dir
            self.timestamp = outer_instance.get_current_timestamp()
            self.csv_scan_file = os.path.join(self.scan_results_dir, f'scan_{network.network_address}_{self.timestamp}.csv')
            self.csv_result_file = os.path.join(self.scan_results_dir, f'result_{network.network_address}_{self.timestamp}.csv')
            self.netkbfile = outer_instance.shared_data.netkbfile
            self.ip_data = None
            self.open_ports = {}
            self.all_ports = []
            self.ip_hostname_list = []

        def scan_network_and_write_to_csv(self):
            self.outer_instance.check_if_csv_scan_file_exists(self.csv_scan_file, self.csv_result_file, self.netkbfile)
            with self.outer_instance.lock:
                try:
                    with open(self.csv_scan_file, 'a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(['IP', 'Hostname', 'MAC Address'])
                except Exception as e:
                    self.outer_instance.logger.error(f"Error in scan_network_and_write_to_csv (initial write): {e}")

            self.outer_instance.nm.scan(hosts=str(self.network), arguments='-sn')
            threads = []
            for host in self.outer_instance.nm.all_hosts():
                t = threading.Thread(target=self.scan_host, args=(host,))
                t.start()
                threads.append(t)

            # Wait for all host scan threads to complete (MAC lookups can be slow)
            for t in threads:
                t.join(timeout=30)  # 30 sec max per thread

            self.outer_instance.sort_and_write_csv(self.csv_scan_file)

        def scan_host(self, ip):
            if self.outer_instance.blacklistcheck and ip in self.outer_instance.ip_scan_blacklist:
                return
            try:
                # Try nmap hostname first, then fallback to reverse DNS
                hostname = self.outer_instance.nm[ip].hostname() if self.outer_instance.nm[ip].hostname() else ''
                if not hostname:
                    hostname = self.outer_instance.get_hostname(ip)
                # Don't use IP as hostname - if hostname equals IP, treat as unknown
                if hostname == ip:
                    hostname = ''
                mac = self.outer_instance.get_mac_address(ip, hostname)
                if not self.outer_instance.blacklistcheck or mac not in self.outer_instance.mac_scan_blacklist:
                    with self.outer_instance.lock:
                        with open(self.csv_scan_file, 'a', newline='') as file:
                            writer = csv.writer(file)
                            writer.writerow([ip, hostname, mac])
                            self.ip_hostname_list.append((ip, hostname, mac))
            except Exception as e:
                self.outer_instance.logger.error(f"Error getting MAC address or writing to file for IP {ip}: {e}")
            self.progress += 1
            time.sleep(0.1)

        def get_progress(self):
            return (self.progress / self.total_ips) * 100

        def start(self):
            self.scan_network_and_write_to_csv()
            # Threads are now joined in scan_network_and_write_to_csv, no need for sleep
            self.ip_data = self.outer_instance.GetIpFromCsv(self.outer_instance, self.csv_scan_file)
            self.open_ports = {ip: [] for ip in self.ip_data.ip_list}

            total_ips = len(self.ip_data.ip_list)
            self.logger.info(f"Scanning {total_ips} IPs for open ports...")

            for i, ip in enumerate(self.ip_data.ip_list):
                if i % 10 == 0:
                    self.logger.info(f"Port scanning progress: {i}/{total_ips}")
                port_scanner = self.outer_instance.PortScanner(self.outer_instance, ip, self.open_ports, self.portstart, self.portend, self.extra_ports)
                port_scanner.start()

            self.all_ports = sorted(list(set(port for ports in self.open_ports.values() for port in ports)))
            alive_ips = set(self.ip_data.ip_list)
            return self.ip_data, self.open_ports, self.all_ports, self.csv_result_file, self.netkbfile, alive_ips

    class LiveStatusUpdater:
        """Uses csv module instead of pandas."""
        def __init__(self, source_csv_path, output_csv_path):
            self.logger = logger
            self.source_csv_path = source_csv_path
            self.output_csv_path = output_csv_path
            self.rows = []
            self.total_open_ports = 0
            self.alive_hosts_count = 0
            self.all_known_hosts_count = 0

        def read_csv(self):
            try:
                self.rows = []
                with open(self.source_csv_path, 'r') as file:
                    reader = csv.DictReader(file)
                    for row in reader:
                        self.rows.append(row)
            except Exception as e:
                self.logger.error(f"Error in read_csv: {e}")

        def calculate_open_ports(self):
            try:
                self.total_open_ports = 0
                for row in self.rows:
                    if row.get('Alive') == '1':
                        ports = row.get('Ports', '')
                        if ports:
                            self.total_open_ports += len(ports.split(';'))
            except Exception as e:
                self.logger.error(f"Error in calculate_open_ports: {e}")

        def calculate_hosts_counts(self):
            try:
                self.all_known_hosts_count = sum(1 for row in self.rows if row.get('MAC Address') != 'STANDALONE')
                self.alive_hosts_count = sum(1 for row in self.rows if row.get('Alive') == '1')
            except Exception as e:
                self.logger.error(f"Error in calculate_hosts_counts: {e}")

        def save_results(self):
            try:
                headers = ['Total Open Ports', 'Alive Hosts Count', 'All Known Hosts Count', 'Vulnerabilities Count']
                row_data = {
                    'Total Open Ports': self.total_open_ports,
                    'Alive Hosts Count': self.alive_hosts_count,
                    'All Known Hosts Count': self.all_known_hosts_count,
                    'Vulnerabilities Count': 0  # Preserved from existing or default to 0
                }

                # Read existing vulnerabilities count if file exists
                if os.path.exists(self.output_csv_path):
                    with open(self.output_csv_path, 'r') as file:
                        reader = csv.DictReader(file)
                        for row in reader:
                            row_data['Vulnerabilities Count'] = row.get('Vulnerabilities Count', 0)
                            break

                # Write updated values (creates file if missing)
                with open(self.output_csv_path, 'w', newline='') as file:
                    writer = csv.DictWriter(file, fieldnames=headers)
                    writer.writeheader()
                    writer.writerow(row_data)
            except Exception as e:
                self.logger.error(f"Error in save_results: {e}")

        def update_livestatus(self):
            try:
                self.read_csv()
                self.calculate_open_ports()
                self.calculate_hosts_counts()
                self.save_results()
                self.logger.info("Livestatus updated")
                self.logger.info(f"Results saved to {self.output_csv_path}")
            except Exception as e:
                self.logger.error(f"Error in update_livestatus: {e}")

        def clean_scan_results(self, scan_results_dir):
            try:
                files = glob.glob(scan_results_dir + '/*')
                files.sort(key=os.path.getmtime)
                for file in files[:-20]:
                    os.remove(file)
                self.logger.info("Scan results cleaned up")
            except Exception as e:
                self.logger.error(f"Error in clean_scan_results: {e}")

    def scan(self, target_network=None):
        start_time = time.time()
        self.logger.lifecycle_start("NetworkScanner")
        try:
            self.shared_data.bjornorch_status = "NetworkScanner"
            self.logger.info(f"Starting Network Scanner")
            # Use specified network or auto-detect
            if target_network:
                import ipaddress
                network = ipaddress.IPv4Network(target_network, strict=False)
                self.logger.info(f"Network: {network} (user selected)")
            else:
                network = self.get_network()
            self.shared_data.bjornstatustext2 = str(network)
            portstart = self.shared_data.portstart
            portend = self.shared_data.portend
            extra_ports = self.shared_data.portlist
            scanner = self.ScanPorts(self, network, portstart, portend, extra_ports)
            ip_data, open_ports, all_ports, csv_result_file, netkbfile, alive_ips = scanner.start()

            alive_macs = set(ip_data.mac_list)

            self.logger.info("Scan Results:")
            self.logger.info(f"Found {len(ip_data.ip_list)} hosts, {len(all_ports)} unique open ports")

            netkb_data = []
            for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                    continue
                netkb_data.append([mac, ip, hostname, ports])

            with self.lock:
                with open(csv_result_file, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["IP", "Hostname", "Alive", "MAC Address"] + [str(port) for port in all_ports])
                    for ip, ports, hostname, mac in zip(ip_data.ip_list, open_ports.values(), ip_data.hostname_list, ip_data.mac_list):
                        if self.blacklistcheck and (mac in self.mac_scan_blacklist or ip in self.ip_scan_blacklist):
                            continue
                        alive = '1' if mac in alive_macs else '0'
                        writer.writerow([ip, hostname, alive, mac] + [str(port) if port in ports else '' for port in all_ports])

            self.update_netkb(netkbfile, netkb_data, alive_macs, network)

            if self.displaying_csv:
                self.display_csv(csv_result_file)

            source_csv_path = self.shared_data.netkbfile
            output_csv_path = self.shared_data.livestatusfile

            updater = self.LiveStatusUpdater(source_csv_path, output_csv_path)
            updater.update_livestatus()
            updater.clean_scan_results(self.shared_data.scan_results_dir)

            duration = time.time() - start_time
            self.logger.lifecycle_end("NetworkScanner", 'success', duration)
        except Exception as e:
            self.logger.error(f"Error in scan: {e}")
            duration = time.time() - start_time
            self.logger.lifecycle_end("NetworkScanner", 'failed', duration)

    def start(self):
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.scan)
            self.thread.start()
            logger.info("NetworkScanner started.")

    def stop(self):
        if self.running:
            self.running = False
            if self.thread.is_alive():
                self.thread.join(timeout=60)  # 60 second timeout for graceful shutdown
                if self.thread.is_alive():
                    logger.warning("NetworkScanner thread did not terminate within 60s timeout")
            logger.info("NetworkScanner stopped.")

if __name__ == "__main__":
    shared_data = SharedData()
    scanner = NetworkScanner(shared_data)
    scanner.scan()
