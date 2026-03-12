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
import device_classifier

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
        # Load OUI database for device classification
        oui_path = os.path.join(self.currentdir, 'share', 'nmap', 'nmap-mac-prefixes')
        self.oui_db = device_classifier.load_oui_database(oui_path)

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
                        writer.writerow(['MAC Address', 'IPs', 'Hostnames', 'Alive', 'Ports', 'Services', 'OS', 'Vendor', 'Device Type'])
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

    def update_netkb(self, netkbfile, netkb_data, alive_macs, scanned_network=None, service_versions=None):
        with self.lock:
            try:
                netkb_entries = {}
                existing_action_columns = []
                core_headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports", "Services", "OS", "Vendor", "Device Type"]
                existing_headers = list(core_headers)

                # Get gateway IP for device classification
                gateway_ip = self.shared_data.get_gateway_ip()

                if os.path.exists(netkbfile):
                    with open(netkbfile, 'r') as file:
                        reader = csv.DictReader(file)
                        if reader.fieldnames:
                            existing_headers = list(reader.fieldnames)
                            # Ensure Services, OS, Vendor and Device Type are in headers (upgrade from old format)
                            ports_idx = existing_headers.index("Ports") if "Ports" in existing_headers else len(existing_headers) - 1
                            insert_at = ports_idx + 1
                            for col in ["Services", "OS", "Vendor", "Device Type"]:
                                if col not in existing_headers:
                                    existing_headers.insert(insert_at, col)
                                insert_at = existing_headers.index(col) + 1
                        existing_action_columns = [header for header in existing_headers if header not in core_headers]
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
                                'Ports': set(ports) if ports[0] else set(),
                                'Services': row.get('Services', ''),
                                'OS': row.get('OS', ''),
                                'Vendor': row.get('Vendor', ''),
                                'Device Type': row.get('Device Type', ''),
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
                            'Ports': set(map(str, ports)),
                            'Services': '',
                            'OS': '',
                            'Vendor': '',
                            'Device Type': '',
                        }
                        for action in existing_action_columns:
                            netkb_entries[mac][action] = ""

                for mac in netkb_entries:
                    if mac not in alive_macs:
                        netkb_entries[mac]['Alive'] = '0'

                # Merge service version data from -sV scan
                if service_versions:
                    for mac, data in netkb_entries.items():
                        host_ip = sorted(data['IPs'], key=self.ip_key)[0] if data['IPs'] else None
                        if host_ip and host_ip in service_versions:
                            sv = service_versions[host_ip]
                            # Merge services: port:service/version pairs
                            if sv.get('services'):
                                # Parse existing services string
                                existing_svc = {}
                                if data.get('Services'):
                                    for part in data['Services'].split(';'):
                                        if ':' in part:
                                            p, s = part.split(':', 1)
                                            existing_svc[p] = s
                                # Merge new services (new data overwrites old)
                                for port, svc in sv['services'].items():
                                    existing_svc[port] = svc
                                # Serialize: sorted by port number
                                data['Services'] = ';'.join(
                                    f"{p}:{existing_svc[p]}"
                                    for p in sorted(existing_svc, key=lambda x: int(x) if x.isdigit() else 0)
                                )
                            # Update OS info (prefer new detection)
                            if sv.get('os'):
                                data['OS'] = sv['os']

                # Classify/re-classify devices (vendor lookup + port + service fingerprinting)
                for mac, data in netkb_entries.items():
                    vendor = data.get('Vendor', '')
                    if not vendor or vendor == 'Unknown':
                        vendor = device_classifier.lookup_vendor(mac, self.oui_db)
                        data['Vendor'] = vendor
                    host_ip = sorted(data['IPs'], key=self.ip_key)[0] if data['IPs'] else None
                    data['Device Type'] = device_classifier.classify_device(
                        vendor, data['Ports'], ip=host_ip, gateway_ip=gateway_ip,
                        services=data.get('Services', ''), os_info=data.get('OS', '')
                    )

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
                            ';'.join(sorted(data['Ports'], key=lambda x: int(x) if x else 0)),
                            data.get('Services', ''),
                            data.get('OS', ''),
                            data.get('Vendor', ''),
                            data.get('Device Type', ''),
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
        def __init__(self, outer_instance, network, portstart, portend, extra_ports, is_manual=False):
            self.outer_instance = outer_instance
            self._is_manual = is_manual
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

        def _build_netkb_data(self):
            """Build netkb_data list from current scan state."""
            data = []
            for ip, ports, hostname, mac in zip(
                self.ip_data.ip_list,
                [self.open_ports.get(ip, []) for ip in self.ip_data.ip_list],
                self.ip_data.hostname_list,
                self.ip_data.mac_list
            ):
                if self.outer_instance.blacklistcheck and (
                    mac in self.outer_instance.mac_scan_blacklist or
                    ip in self.outer_instance.ip_scan_blacklist
                ):
                    continue
                data.append([mac, ip, hostname, ports])
            return data

        def _write_netkb_incremental(self, service_versions=None):
            """Write current scan state to netkb and update livestatus counters."""
            netkb_data = self._build_netkb_data()
            alive_macs = set(self.ip_data.mac_list)
            self.outer_instance.update_netkb(
                self.netkbfile, netkb_data, alive_macs,
                self.network, service_versions=service_versions
            )
            # Update livestatus so dashboard counters refresh too
            try:
                updater = self.outer_instance.LiveStatusUpdater(
                    self.netkbfile,
                    self.outer_instance.shared_data.livestatusfile
                )
                updater.update_livestatus()
            except Exception as e:
                self.logger.warning(f"Livestatus update failed: {e}")

        def _should_stop(self):
            """Check if scanning should stop."""
            sd = self.outer_instance.shared_data
            if getattr(sd, 'orchestrator_should_exit', False):
                return True
            # If scan was started by orchestrator (not manual), stop on manual_mode
            if not self._is_manual and getattr(sd, 'manual_mode', False):
                return True
            return False

        def start(self):
            sd = self.outer_instance.shared_data

            # Phase 1: Host discovery
            sd.lokistatustext2 = "Discovering hosts..."
            self.scan_network_and_write_to_csv()
            if self._should_stop():
                return self.ip_data if hasattr(self, 'ip_data') else None, {}, [], None, None, set()
            self.ip_data = self.outer_instance.GetIpFromCsv(self.outer_instance, self.csv_scan_file)
            self.open_ports = {ip: [] for ip in self.ip_data.ip_list}

            total_ips = len(self.ip_data.ip_list)
            sd.lokistatustext2 = f"Found {total_ips} hosts"
            self.logger.info(f"Found {total_ips} hosts")
            self._write_netkb_incremental()

            # Phase 2: Port scanning
            sd.lokistatustext2 = f"Scanning ports on {total_ips} hosts..."
            self.logger.info(f"Scanning {total_ips} IPs for open ports...")

            for i, ip in enumerate(self.ip_data.ip_list):
                if self._should_stop():
                    break
                if i % 10 == 0:
                    self.logger.info(f"Port scanning progress: {i}/{total_ips}")
                port_scanner = self.outer_instance.PortScanner(self.outer_instance, ip, self.open_ports, self.portstart, self.portend, self.extra_ports)
                port_scanner.start()

            self.all_ports = sorted(list(set(port for ports in self.open_ports.values() for port in ports)))
            alive_ips = set(self.ip_data.ip_list)

            sd.lokistatustext2 = f"{len(self.all_ports)} open ports found"
            self._write_netkb_incremental()

            if self._should_stop():
                return self.ip_data, self.open_ports, self.all_ports, self.csv_result_file, self.netkbfile, alive_ips

            # Phase 3: Service fingerprinting (writes per-host)
            self.service_versions = {}
            if self.outer_instance.shared_data.service_version_detection:
                self._run_version_detection()

            if self._should_stop():
                return self.ip_data, self.open_ports, self.all_ports, self.csv_result_file, self.netkbfile, alive_ips

            # Phase 4: OS fingerprinting
            if self.outer_instance.shared_data.os_detection:
                self._run_os_detection()

            return self.ip_data, self.open_ports, self.all_ports, self.csv_result_file, self.netkbfile, alive_ips

        # Scripts for service fingerprinting (replaces -sV which crashes on MIPS).
        # banner: grabs greeting banners (SSH, FTP, SMTP)
        # http-server-header/http-title: probes HTTP services
        # mysql-info: probes MySQL/MariaDB version
        # smb-protocols: SMB version detection (smb-os-discovery crashes on MIPS)
        # rdp-ntlm-info: probes RDP version info
        # nbstat: NetBIOS name for port 139
        PROBE_SCRIPTS = 'banner,http-server-header,http-title,mysql-info,smb-protocols,rdp-ntlm-info,nbstat'

        def _run_version_detection(self):
            """Run nmap probe scripts on hosts with open ports for service fingerprinting.

            Uses multiple NSE scripts instead of -sV because the MIPS nmap build
            crashes on -sV due to missing OpenSSL DTLS support.
            Results are written to netkb after each host completes.
            """
            sd = self.outer_instance.shared_data
            hosts_with_ports = [(ip, self.open_ports.get(ip, [])) for ip in self.ip_data.ip_list]
            hosts_with_ports = [(ip, ports) for ip, ports in hosts_with_ports if ports]
            total = len(hosts_with_ports)

            for i, (ip, ports) in enumerate(hosts_with_ports):
                if self._should_stop():
                    break
                port_str = ','.join(str(p) for p in sorted(ports))
                sd.lokistatustext2 = f"Identifying services {i+1}/{total}"
                try:
                    cmd = ['nmap', f'--script={self.PROBE_SCRIPTS}', '-p', port_str, ip]
                    self.logger.info(f"Service detection [{i+1}/{total}] {ip} ports {port_str}")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    if result.returncode != 0:
                        self.logger.warning(f"Service detection failed for {ip}: exit {result.returncode}")
                        continue
                    self._parse_version_output(ip, result.stdout)
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"Service detection timed out for {ip}, continuing without")
                except Exception as e:
                    self.logger.error(f"Service detection error for {ip}: {e}")

                # Write results after each host so UI updates incrementally
                self._write_netkb_incremental(service_versions=self.service_versions)

            sd.lokistatustext2 = f"Services identified on {total} hosts"

        def _sanitize_banner(self, banner):
            """Strip non-printable chars, ANSI escapes, and telnet control sequences from banner text."""
            import re
            # Remove ANSI escape sequences (e.g. \x1B[2J, \x1B[1;1H)
            banner = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', banner)
            # Remove telnet IAC sequences (xFF followed by command + option bytes)
            banner = re.sub(r'\xff[\xf0-\xff].?', '', banner)
            # Remove all remaining non-printable chars (keep space through tilde + common extended)
            banner = re.sub(r'[^\x20-\x7e]', '', banner)
            # Collapse whitespace and trim
            banner = re.sub(r'\s+', ' ', banner).strip()
            return banner

        def _parse_version_output(self, ip, output):
            """Parse nmap probe script output to extract service + version info.

            Handles output from: banner, http-server-header, http-title,
            mysql-info, smb-os-discovery (host script), rdp-ntlm-info.
            """
            import re
            services = {}       # port -> service name (from port table)
            port_versions = {}  # port -> version string (from scripts)
            host_os = ''
            current_port = None
            in_host_scripts = False

            for line in output.splitlines():
                # Detect "Host script results:" section (smb-os-discovery lives here)
                if 'Host script results:' in line:
                    in_host_scripts = True
                    current_port = None
                    continue

                # Port table: "22/tcp   open  ssh"
                m = re.match(r'^(\d+)/tcp\s+open\s+(\S+)', line)
                if m:
                    current_port = m.group(1)
                    services[current_port] = m.group(2)
                    in_host_scripts = False
                    continue

                # |_banner: SSH-2.0-OpenSSH_9.6  or  | banner: ...
                m = re.match(r'^\|_?banner:\s*(.*)', line)
                if m and current_port:
                    v = self._sanitize_banner(m.group(1))
                    if v:
                        port_versions.setdefault(current_port, v)
                    continue

                # |_http-server-header: Apache/2.4.51 (Debian)
                m = re.match(r'^\|_http-server-header:\s*(.*)', line)
                if m and current_port:
                    v = self._sanitize_banner(m.group(1))
                    if v:
                        port_versions[current_port] = v
                    continue

                # |_http-title: Welcome Page
                m = re.match(r'^\|_http-title:\s*(.*)', line)
                if m and current_port:
                    v = self._sanitize_banner(m.group(1))
                    if v and current_port not in port_versions:
                        port_versions[current_port] = v
                    continue

                # |   Version: 5.5.5-10.6.12-MariaDB  (from mysql-info)
                m = re.match(r'^\|\s+Version:\s*(.*)', line)
                if m and current_port:
                    v = self._sanitize_banner(m.group(1))
                    if v:
                        port_versions[current_port] = v
                    continue

                # smb-protocols dialects (host script): "NT LM 0.12 (SMBv1)", "2:0:2", "3:1:1"
                # Collect highest SMB version for port 445
                m = re.match(r'^\|\s+(NT LM \S+.*|[23]:\d+:\d+)', line)
                if m and in_host_scripts:
                    dialect = self._sanitize_banner(m.group(1)).strip()
                    if dialect:
                        smb_port = '445' if '445' in services else ('139' if '139' in services else None)
                        if smb_port:
                            # Keep highest version: prefer "3:1:1" over "2:0:2" over "NT LM"
                            prev = port_versions.get(smb_port, '')
                            if dialect.startswith('3') or not prev or prev.startswith('NT'):
                                port_versions[smb_port] = f"SMBv{dialect}" if not dialect.startswith('NT') else dialect
                    continue

                # nbstat: "| nbstat: NetBIOS name: HOSTNAME, ..."
                m = re.match(r'^\|\s*nbstat:\s*NetBIOS name:\s*(\S+)', line)
                if m:
                    name = self._sanitize_banner(m.group(1).rstrip(','))
                    if name and '139' in services:
                        port_versions.setdefault('139', name)
                    continue

                # |   Product_Version: 10.0.17763  (from rdp-ntlm-info)
                m = re.match(r'^\|\s+Product_Version:\s*(.*)', line)
                if m and current_port:
                    v = self._sanitize_banner(m.group(1))
                    if v:
                        port_versions[current_port] = v
                    continue

            # Build final services dict: port -> "service/version" or "service"
            final = {}
            for port, svc_name in services.items():
                version = port_versions.get(port, '')
                final[port] = f"{svc_name}/{version}" if version else svc_name

            # Infer OS from service banners if not already detected
            if not host_os:
                host_os = self._infer_os_from_banners(final)

            self.service_versions[ip] = {
                'services': final,
                'os': host_os
            }

        # Ordered list of (pattern, os_label) for banner-based OS inference.
        # First match wins, so more specific patterns come first.
        _BANNER_OS_PATTERNS = [
            # Distro-specific (from SSH, Apache, FTP banners)
            (r'Debian|deb\d+u', 'Linux (Debian)'),
            (r'Ubuntu|ubuntu', 'Linux (Ubuntu)'),
            (r'CentOS|centos', 'Linux (CentOS)'),
            (r'Red Hat|RedHat|\.el\d', 'Linux (RHEL)'),
            (r'Fedora', 'Linux (Fedora)'),
            (r'Raspbian|RASPWN|raspberrypi', 'Linux (Raspbian)'),
            (r'OpenWrt|LEDE', 'Linux (OpenWrt)'),
            (r'FreeBSD', 'FreeBSD'),
            # Device-specific
            (r'NETGEAR|ReadyNAS|netgear', 'Linux (Netgear)'),
            (r'hue personal|Philips', 'Embedded (Philips Hue)'),
            (r'eero', 'Embedded (eero)'),
            # OS family from Windows markers
            (r'WIN-|WINDOWS|Windows|microsoft-ds|Product_Version.*10\.0', 'Windows'),
            # Generic Linux markers
            (r'vsFTPd|ProFTPD|OpenSSH.*\d', 'Linux'),
            (r'Apache/', 'Linux'),
            (r'openresty', 'Linux'),
        ]

        def _infer_os_from_banners(self, services_dict):
            """Infer OS from service version banners.

            Scans all service/version strings for known OS patterns.
            Returns the most specific match or empty string.
            """
            import re
            # Combine all service strings into one blob for matching
            blob = ' '.join(services_dict.values())
            if not blob:
                return ''

            for pattern, os_label in self._BANNER_OS_PATTERNS:
                if re.search(pattern, blob, re.IGNORECASE):
                    return os_label
            return ''

        def _run_os_detection(self):
            """Run nmap -O on hosts with open ports for OS fingerprinting.

            Skips hosts that already have OS info from service detection.
            Results merge into service_versions[ip]['os'] and flow into netkb.
            """
            import re
            sd = self.outer_instance.shared_data
            hosts_with_ports = [(ip, self.open_ports.get(ip, [])) for ip in self.ip_data.ip_list]
            hosts_with_ports = [(ip, ports) for ip, ports in hosts_with_ports if ports]

            # Run on all hosts with open ports — combines with banner-inferred OS
            hosts_to_scan = hosts_with_ports

            total = len(hosts_to_scan)
            if total == 0:
                self.logger.info("OS detection: no hosts with open ports")
                return

            self.logger.info(f"OS detection: scanning {total} hosts")

            for i, (ip, ports) in enumerate(hosts_to_scan):
                if self._should_stop():
                    break
                port_str = ','.join(str(p) for p in sorted(ports))
                sd.lokistatustext2 = f"OS detection {i+1}/{total}"
                try:
                    cmd = ['nmap', '-O', '--osscan-limit', '-p', port_str, ip]
                    self.logger.info(f"OS detection [{i+1}/{total}] {ip}")
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                    # Parse output even on non-zero exit — nmap -O may produce
                    # sendto permission warnings (non-zero rc) but still detect OS
                    self._parse_os_output(ip, result.stdout)
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"OS detection timed out for {ip}")
                except Exception as e:
                    self.logger.error(f"OS detection error for {ip}: {e}")

                # Write results after each host so UI updates incrementally
                self._write_netkb_incremental(service_versions=self.service_versions)

            sd.lokistatustext2 = f"OS detected on {total} hosts"

        def _parse_os_output(self, ip, output):
            """Parse nmap -O output and combine with banner-inferred OS.

            Looks for 'OS details:' (best-match summary) with fallback to 'Running:'.
            Combines with any existing banner-inferred OS:
            - If they agree (same OS family), use the more specific one
            - If they disagree, show both: "banner_os | nmap: nmap_os"
            """
            import re
            nmap_os = ''

            # Primary: "OS details: Linux 4.15 - 5.8, Microsoft Windows 10"
            m = re.search(r'OS details:\s*(.+)', output)
            if m:
                nmap_os = m.group(1).strip()
            else:
                # Fallback: "Running (JUST GUESSING): Microsoft Windows 11 (96%)"
                m = re.search(r'Running(?:\s*\(JUST GUESSING\))?:\s*(.+)', output)
                if m:
                    nmap_os = m.group(1).strip()

            if not nmap_os:
                return

            nmap_os = nmap_os[:100]

            # Ensure entry exists
            if ip not in self.service_versions:
                self.service_versions[ip] = {'services': {}, 'os': ''}

            banner_os = self.service_versions[ip].get('os', '')

            if not banner_os:
                # No banner OS — use nmap result
                self.service_versions[ip]['os'] = nmap_os
            else:
                # Both exist — check if they agree on OS family
                banner_lower = banner_os.lower()
                nmap_lower = nmap_os.lower()
                same_family = (
                    ('linux' in banner_lower and 'linux' in nmap_lower) or
                    ('windows' in banner_lower and ('windows' in nmap_lower or 'microsoft' in nmap_lower)) or
                    ('freebsd' in banner_lower and 'freebsd' in nmap_lower)
                )
                if same_family:
                    # Agree — use banner if it's more specific (has distro), else nmap
                    if '(' in banner_os:
                        self.service_versions[ip]['os'] = banner_os
                    else:
                        self.service_versions[ip]['os'] = nmap_os
                else:
                    # Disagree — show both
                    self.service_versions[ip]['os'] = f"{banner_os} | nmap: {nmap_os}"

            self.logger.info(f"OS for {ip}: {self.service_versions[ip]['os']}")

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
                self.logger.debug("Livestatus updated")
                self.logger.debug(f"Results saved to {self.output_csv_path}")
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
            # Refresh blacklists from shared_data (may have changed since init)
            self.blacklistcheck = self.shared_data.blacklistcheck
            self.mac_scan_blacklist = self.shared_data.mac_scan_blacklist
            self.ip_scan_blacklist = self.shared_data.ip_scan_blacklist
            self.shared_data.lokiorch_status = "NetworkScanner"
            self.logger.info(f"Starting Network Scanner (IP blacklist: {self.ip_scan_blacklist})")
            # Use specified network or auto-detect
            if target_network:
                import ipaddress
                network = ipaddress.IPv4Network(target_network, strict=False)
                self.logger.info(f"Network: {network} (user selected)")
            else:
                network = self.get_network()
            self.shared_data.lokistatustext2 = str(network)
            portstart = self.shared_data.portstart
            portend = self.shared_data.portend
            extra_ports = self.shared_data.portlist
            is_manual = target_network is not None
            scanner = self.ScanPorts(self, network, portstart, portend, extra_ports, is_manual=is_manual)
            ip_data, open_ports, all_ports, csv_result_file, netkbfile, alive_ips = scanner.start()

            if ip_data is None:
                self.logger.info("Scan was interrupted before host discovery completed")
                duration = time.time() - start_time
                self.logger.lifecycle_end("NetworkScanner", 'interrupted', duration)
                return

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

            self.update_netkb(netkbfile, netkb_data, alive_macs, network,
                             service_versions=getattr(scanner, 'service_versions', None))

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
