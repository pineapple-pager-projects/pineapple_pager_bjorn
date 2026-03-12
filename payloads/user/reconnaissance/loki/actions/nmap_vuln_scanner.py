# nmap_vuln_scanner.py
# This script performs vulnerability scanning using Nmap on specified IP addresses.
# It scans for vulnerabilities on various ports and saves the results and progress.

import os
import csv
import subprocess
import logging
import time
import re
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from shared import SharedData
from logger import Logger
from cve_lookup import KevDatabase, NvdClient, enrich_findings

logger = Logger(name="nmap_vuln_scanner.py", level=logging.INFO)

b_class = "NmapVulnScanner"
b_module = "nmap_vuln_scanner"
b_status = "vuln_scan"
b_port = None
b_parent = None

class NmapVulnScanner:
    """
    This class handles the Nmap vulnerability scanning process.
    """
    # HTTP ports get batched scanning to avoid MIPS CPU starvation
    HTTP_PORTS = {'80', '443', '8080', '8443'}

    # SSL/TLS ports for cipher and vulnerability analysis
    SSL_PORTS = {'443', '8443', '993', '995', '636', '587'}

    # DNS ports for reconnaissance
    DNS_PORTS = {'53'}

    # SNMP ports for enumeration (UDP)
    SNMP_PORTS = {'161'}

    # Port-to-enumeration-scripts mapping (discovery/safe scripts)
    # Note: smb-os-discovery excluded — crashes on MIPS
    ENUM_SCRIPTS = {
        # Common services
        '21':   ("FTP enumeration", "ftp-anon,ftp-syst", 15),
        '22':   ("SSH enumeration", "ssh2-enum-algos,ssh-hostkey", 15),
        '23':   ("Telnet enumeration", "telnet-ntlm-info,telnet-encryption", 15),
        '25':   ("SMTP enumeration", "smtp-enum-users,smtp-ntlm-info", 30),
        '79':   ("Finger enumeration", "finger", 15),
        '110':  ("POP3 enumeration", "pop3-capabilities,pop3-ntlm-info", 15),
        '111':  ("RPC enumeration", "rpcinfo", 15),
        '139':  ("NetBIOS/SMB enumeration", "smb-enum-shares,smb-enum-users,smb-security-mode,smb-protocols,smb2-security-mode", 45),
        '143':  ("IMAP enumeration", "imap-capabilities,imap-ntlm-info", 15),
        '389':  ("LDAP enumeration", "ldap-rootdse,ldap-search", 15),
        '445':  ("SMB enumeration", "smb-enum-shares,smb-enum-users,smb-security-mode,smb-protocols,smb2-security-mode", 45),
        '548':  ("AFP enumeration", "afp-serverinfo,afp-showmount", 15),
        '554':  ("RTSP enumeration", "rtsp-methods", 15),
        '631':  ("CUPS enumeration", "cups-info,cups-queue-info", 15),
        '873':  ("Rsync enumeration", "rsync-list-modules", 15),
        '1099': ("Java RMI enumeration", "rmi-dumpregistry", 15),
        '1433': ("MS-SQL enumeration", "ms-sql-info,ms-sql-ntlm-info", 15),
        '1521': ("Oracle enumeration", "oracle-tns-version", 15),
        '1883': ("MQTT enumeration", "mqtt-subscribe", 15),
        '2049': ("NFS enumeration", "nfs-showmount", 15),
        '3260': ("iSCSI enumeration", "iscsi-info", 15),
        '3306': ("MySQL enumeration", "mysql-info", 15),
        '3389': ("RDP enumeration", "rdp-enum-encryption,rdp-ntlm-info", 15),
        '5060': ("SIP enumeration", "sip-methods", 15),
        '5222': ("XMPP enumeration", "xmpp-info", 15),
        '5672': ("AMQP enumeration", "amqp-info", 15),
        '5900': ("VNC enumeration", "vnc-info,realvnc-auth-bypass", 15),
        '6379': ("Redis enumeration", "redis-info", 15),
        '11211':("Memcached enumeration", "memcached-info", 15),
        '27017':("MongoDB enumeration", "mongodb-info,mongodb-databases", 15),
    }

    SSL_SCRIPTS = [
        ("SSL/TLS analysis",
         "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-ccs-injection",
         45),
    ]

    DNS_SCRIPTS = [
        ("DNS reconnaissance",
         "dns-zone-transfer,dns-brute,dns-cache-snoop,dns-recursion,dns-nsid",
         60),
    ]

    SNMP_SCRIPTS = [
        ("SNMP enumeration",
         "snmp-info,snmp-brute,snmp-sysdescr,snmp-netstat,snmp-processes",
         45,
         "snmp-brute.communitiesdb=public,private,community"),
    ]

    # HTTP vuln scripts split into batches of ~15-20 for MIPS compatibility.
    # Running all 56 concurrently on MIPS produces zero output; batching works.
    HTTP_VULN_BATCHES = [
        # Batch 1: CVE checks (targeted, fast)
        ("CVE checks",
         "http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,"
         "http-vuln-cve2010-2861,http-vuln-cve2011-3192,http-vuln-cve2011-3368,"
         "http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-6786,"
         "http-vuln-cve2013-7091,http-vuln-cve2014-2126,http-vuln-cve2014-2127,"
         "http-vuln-cve2014-2128,http-vuln-cve2014-2129,http-vuln-cve2014-3704,"
         "http-vuln-cve2014-8877,http-vuln-cve2015-1427,http-vuln-cve2015-1635,"
         "http-vuln-cve2017-1001000,http-vuln-cve2017-5638",
         30),  # script-timeout
        # Batch 2: More CVEs + backdoor/device checks
        ("Backdoor and device checks",
         "http-vuln-cve2017-5689,http-vuln-cve2017-8917,http-vuln-misfortune-cookie,"
         "http-vuln-wnr1000-creds,http-shellshock,http-git,http-passwd,"
         "http-dlink-backdoor,http-huawei-hg5xx-vuln,http-tplink-dir-traversal,"
         "http-vmware-path-vuln,http-phpmyadmin-dir-traversal,http-iis-webdav-vuln,"
         "http-frontpage-login,http-adobe-coldfusion-apsa1301,http-avaya-ipoffice-users,"
         "http-awstatstotals-exec,http-axis2-dir-traversal",
         30,
         "http-shellshock.uri=/cgi-bin/status.sh"),
        # Batch 3: Path enumeration (http-enum needs >100s on MIPS, own batch)
        ("Path enumeration",
         "http-enum",
         120),
        # Batch 4: Config checks (fast scripts)
        ("Config checks",
         "http-cookie-flags,http-cross-domain-policy,http-trace,"
         "http-internal-ip-disclosure,http-aspnet-debug,http-jsonp-detection,"
         "http-method-tamper,http-litespeed-sourcecode-download,"
         "http-majordomo2-dir-traversal,http-wordpress-users,http-phpself-xss",
         30,
         "http-method-tamper.paths={/admin/index.php}"),
        # Batch 5: Crawlers (heavier, longer timeout)
        ("Crawler checks",
         "http-csrf,http-dombased-xss,http-stored-xss,http-sql-injection,"
         "http-fileupload-exploiter",
         60),
        # Batch 6: Slowloris MUST be last — it exhausts server connections
        ("Slowloris check",
         "http-slowloris-check",
         60),
        # Batch 7: CMS and web enumeration
        ("Web enumeration",
         "http-wordpress-enum,http-drupal-enum,http-auth-finder,http-robots.txt",
         60),
    ]

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.scan_results = []
        self.summary_file = self.shared_data.vuln_summary_file
        self.create_summary_file()
        self._check_nse_available()
        self._init_threat_intel()
        logger.debug("NmapVulnScanner initialized.")

    def _init_threat_intel(self):
        """Initialize KEV database, optional NVD client, and vulners availability."""
        kev_path = os.path.join(self.shared_data.currentdir, 'data', 'kev_catalog.json')
        self.kev_db = KevDatabase(kev_path)

        self.nvd_client = None
        if getattr(self.shared_data, 'enable_nvd_lookup', False) and getattr(self.shared_data, 'nvd_api_key', ''):
            cache_path = os.path.join(self.shared_data.currentdir, 'data', 'nvd_cache.json')
            self.nvd_client = NvdClient(api_key=self.shared_data.nvd_api_key, cache_path=cache_path)
            logger.debug("NVD API client initialized for CVSS enrichment")

        # Check vulners.nse availability (requires internet)
        self._vulners_available = False
        if getattr(self.shared_data, 'enable_vulners_lookup', False):
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(('vulners.com', 443))
                s.close()
                self._vulners_available = True
                logger.info("Vulners lookup enabled")
            except Exception:
                logger.info("Vulners lookup disabled (no internet)")

    def _update_vuln_counter(self):
        """Update shared_data.vulnnbr from vulnerability_summary.csv."""
        try:
            if os.path.exists(self.summary_file):
                with open(self.summary_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    total = 0
                    for row in reader:
                        vulns = row.get("Vulnerabilities", "").strip()
                        if vulns:
                            total += len([v for v in vulns.split("; ") if v.strip()])
                    self.shared_data.vulnnbr = total
        except Exception:
            pass

    def _check_nse_available(self):
        """Check if nmap NSE scripts are available. Logs warning if not."""
        nmapdir = os.environ.get('NMAPDIR', '/usr/share/nmap')
        scripts_dir = os.path.join(nmapdir, 'scripts')
        if not os.path.isdir(scripts_dir):
            logger.error(f"NSE scripts directory not found: {scripts_dir}")
            logger.error("Vulnerability scanning will not work. Install nmap-full or bundle scripts.")
            self.nse_available = False
            return
        # Spot-check a few scripts we actually use
        test_scripts = ['http-enum.nse', 'http-vuln-cve2017-5638.nse']
        found = sum(1 for s in test_scripts if os.path.exists(os.path.join(scripts_dir, s)))
        if found == 0:
            logger.error(f"NSE scripts not found in {scripts_dir} — vuln scanning will not work")
            self.nse_available = False
            return
        logger.debug(f"NSE scripts verified in {scripts_dir} ({len(os.listdir(scripts_dir))} scripts)")
        self.nse_available = True

    def create_summary_file(self):
        """
        Creates a summary file for vulnerabilities if it does not exist.
        """
        if not os.path.exists(self.summary_file):
            os.makedirs(self.shared_data.vulnerabilities_dir, exist_ok=True)
            with open(self.summary_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])

    def update_summary_file(self, ip, hostname, mac, port, vulnerabilities):
        """
        Updates the summary file with the scan results.
        """
        try:
            # Read existing data
            rows = []
            if os.path.exists(self.summary_file):
                with open(self.summary_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)

            # Add new data
            new_row = {"IP": ip, "Hostname": hostname, "MAC Address": mac, "Port": port, "Vulnerabilities": vulnerabilities}
            rows.append(new_row)

            # Remove duplicates based on IP and MAC Address, keeping the last occurrence
            seen = {}
            for row in rows:
                key = (row.get("IP", ""), row.get("MAC Address", ""))
                seen[key] = row
            rows = list(seen.values())

            # Save the updated data back to the summary file
            with open(self.summary_file, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                writer.writeheader()
                writer.writerows(rows)
        except Exception as e:
            logger.error(f"Error updating summary file: {e}")


    def _run_nmap_scripts(self, ip, port, scripts, script_timeout, batch_timeout,
                          hostname=None, extra_args=None):
        """Run a set of nmap scripts against ip:port. Returns (stdout, success)."""
        try:
            cmd = ["nmap", self.shared_data.nmap_scan_aggressivity,
                 "--script", scripts,
                 "--script-timeout", f"{script_timeout}s"]
            # Build script-args: hostname + any batch-specific args
            args_parts = []
            if hostname:
                args_parts.append(f"http.host={hostname}")
            if extra_args:
                args_parts.append(extra_args)
            if args_parts:
                cmd.extend(["--script-args", ",".join(args_parts)])
            cmd.extend(["-p", port, ip])
            start = time.time()
            # Ensure subprocess outlives nmap's script-timeout to avoid race condition
            effective_timeout = max(batch_timeout, script_timeout + 30)
            result = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=effective_timeout
            )
            elapsed = time.time() - start
            # Warn only if nmap returned suspiciously fast with no output —
            # indicates scripts failed to load, not just "no vulns found"
            if result.returncode == 0 and '|' not in result.stdout and elapsed < 5:
                logger.warning(f"nmap returned no script output in {elapsed:.1f}s for {ip}:{port} — NSE scripts may not be installed")
            return result.stdout, True
        except subprocess.TimeoutExpired:
            return "", False
        except Exception as e:
            logger.error(f"Error running scripts on {ip}:{port}: {e}")
            return "", False

    def _scan_http_port(self, ip, port, hostname=None):
        """Scan an HTTP port using batched scripts to avoid MIPS CPU starvation."""
        combined = ""
        batches_succeeded = 0
        batch_timeout = getattr(self.shared_data, 'vuln_scan_timeout', 120)

        for batch in self.HTTP_VULN_BATCHES:
            if self.shared_data.orchestrator_should_exit:
                break
            batch_name, scripts, script_timeout = batch[0], batch[1], batch[2]
            extra_args = batch[3] if len(batch) > 3 else None
            logger.info(f"Vuln scanning {ip}:{port} - {batch_name}..." + (f" (Host: {hostname})" if hostname else ""))
            self.shared_data.lokistatustext2 = f"{ip}:{port} {batch_name}"
            stdout, ok = self._run_nmap_scripts(ip, port, scripts, script_timeout,
                                                batch_timeout, hostname=hostname,
                                                extra_args=extra_args)
            if ok:
                combined += stdout
                batches_succeeded += 1
            else:
                logger.warning(f"Batch '{batch_name}' timeout on {ip}:{port} after {batch_timeout}s")

        return combined, batches_succeeded > 0

    def _scan_regular_port(self, ip, port):
        """Scan a non-HTTP port with --script vuln in a single call."""
        port_timeout = getattr(self.shared_data, 'vuln_scan_timeout', 120)
        scripts = "vuln"
        if self._vulners_available:
            scripts = "vuln,vulners"
        logger.info(f"Vuln scanning {ip} port {port}...")
        stdout, ok = self._run_nmap_scripts(ip, port, scripts, 30, port_timeout)
        if not ok:
            logger.warning(f"Vuln scan timeout on {ip}:{port} after {port_timeout}s, moving to next port")
        return stdout, ok

    def _scan_ssl_port(self, ip, port):
        """Scan an SSL/TLS port for cipher and certificate vulnerabilities."""
        batch_timeout = getattr(self.shared_data, 'vuln_scan_timeout', 120)
        combined = ""
        for batch in self.SSL_SCRIPTS:
            batch_name, scripts, script_timeout = batch[0], batch[1], batch[2]
            logger.info(f"SSL scanning {ip}:{port} - {batch_name}")
            self.shared_data.lokistatustext2 = f"{ip}:{port} {batch_name}"
            stdout, ok = self._run_nmap_scripts(ip, port, scripts, script_timeout, batch_timeout)
            if ok:
                combined += stdout
        return combined, bool(combined)

    def _scan_dns_port(self, ip, port):
        """Scan a DNS port for zone transfer, brute force, and cache snooping."""
        batch_timeout = getattr(self.shared_data, 'vuln_scan_timeout', 120)
        combined = ""
        for batch in self.DNS_SCRIPTS:
            batch_name, scripts, script_timeout = batch[0], batch[1], batch[2]
            logger.info(f"DNS scanning {ip}:{port} - {batch_name}")
            self.shared_data.lokistatustext2 = f"{ip}:{port} {batch_name}"
            stdout, ok = self._run_nmap_scripts(ip, port, scripts, script_timeout, batch_timeout)
            if ok:
                combined += stdout
        return combined, bool(combined)

    def _scan_snmp_port(self, ip, port):
        """Scan an SNMP port (UDP) for enumeration and community string brute force."""
        batch_timeout = getattr(self.shared_data, 'vuln_scan_timeout', 120)
        combined = ""
        for batch in self.SNMP_SCRIPTS:
            batch_name, scripts, script_timeout = batch[0], batch[1], batch[2]
            extra_args = batch[3] if len(batch) > 3 else None
            logger.info(f"SNMP scanning {ip}:{port} - {batch_name}")
            self.shared_data.lokistatustext2 = f"{ip}:{port} {batch_name}"
            # SNMP uses UDP — inject -sU into the command
            try:
                cmd = ["nmap", self.shared_data.nmap_scan_aggressivity,
                     "-sU", "--script", scripts,
                     "--script-timeout", f"{script_timeout}s"]
                if extra_args:
                    cmd.extend(["--script-args", extra_args])
                cmd.extend(["-p", port, ip])
                effective_timeout = max(batch_timeout, script_timeout + 30)
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=effective_timeout)
                combined += result.stdout
            except subprocess.TimeoutExpired:
                logger.warning(f"SNMP scan timeout on {ip}:{port}")
            except Exception as e:
                logger.error(f"Error in SNMP scan on {ip}:{port}: {e}")
        return combined, bool(combined)

    def _run_enumeration(self, ip, port, batch_timeout):
        """Run discovery/safe enumeration scripts for a port if available."""
        entry = self.ENUM_SCRIPTS.get(port)
        if not entry:
            return "", False
        enum_name, scripts, script_timeout = entry
        logger.info(f"Enumerating {ip}:{port} - {enum_name}")
        self.shared_data.lokistatustext2 = f"{ip}:{port} {enum_name}"
        return self._run_nmap_scripts(ip, port, scripts, script_timeout, batch_timeout)

    def scan_vulnerabilities(self, ip, hostname, mac, ports):
        combined_result = ""
        all_vulnerabilities = set()
        all_details = []
        ports_succeeded = 0

        # Skip port 139 (NetBIOS-SSN) when 445 (SMB) is present —
        # SMB vuln scripts only work on 445; scanning 139 wastes time and duplicates results
        port_set = set(p.strip() for p in ports)
        if '445' in port_set and '139' in port_set:
            ports = [p for p in ports if p.strip() != '139']
            logger.info(f"Skipping port 139 (redundant with 445) for {ip}")

        self.shared_data.lokistatustext2 = ip
        logger.info(f"Scanning {ip} on {len(ports)} ports for vulnerabilities with aggressivity {self.shared_data.nmap_scan_aggressivity}")

        for port in ports:
            if self.shared_data.orchestrator_should_exit:
                break

            # Route port to appropriate scanner
            if port in self.HTTP_PORTS:
                stdout, ok = self._scan_http_port(ip, port, hostname=hostname if hostname else None)
                # HTTPS ports also get SSL analysis
                if port in self.SSL_PORTS:
                    ssl_out, ssl_ok = self._scan_ssl_port(ip, port)
                    if ssl_ok:
                        combined_result += ssl_out
                        details = self.parse_vulnerability_details(ssl_out)
                        if details:
                            all_details.extend(details)
                        vulns = self.parse_vulnerabilities(ssl_out)
                        if vulns:
                            for v in vulns.split("; "):
                                if v.strip():
                                    all_vulnerabilities.add(v.strip())
            elif port in self.DNS_PORTS:
                stdout, ok = self._scan_dns_port(ip, port)
            elif port in self.SNMP_PORTS:
                stdout, ok = self._scan_snmp_port(ip, port)
            elif port in self.SSL_PORTS:
                # Non-HTTP SSL ports (IMAPS, POP3S, LDAPS)
                stdout, ok = self._scan_ssl_port(ip, port)
                regular_out, regular_ok = self._scan_regular_port(ip, port)
                if regular_ok:
                    stdout = (stdout or '') + regular_out
                    ok = True
            else:
                stdout, ok = self._scan_regular_port(ip, port)

            # Run enumeration scripts after vuln scan for this port
            if self.shared_data.scan_enumeration:
                batch_timeout = getattr(self.shared_data, 'vuln_scan_timeout', 120)
                enum_out, enum_ok = self._run_enumeration(ip, port, batch_timeout)
                if enum_ok and enum_out:
                    stdout = (stdout or '') + enum_out

            if ok:
                combined_result += stdout
                ports_succeeded += 1

                vulns = self.parse_vulnerabilities(stdout)
                if vulns:
                    for v in vulns.split("; "):
                        if v.strip():
                            all_vulnerabilities.add(v.strip())
                    logger.info(f"Vulnerabilities found on {ip}:{port}: {vulns}")

                details = self.parse_vulnerability_details(stdout)
                if details:
                    all_details.extend(details)

                # Incremental write: flush findings to disk after each port
                if all_vulnerabilities:
                    merged_vulns = "; ".join(sorted(all_vulnerabilities))
                    scanned_ports_so_far = ",".join(ports[:ports.index(port) + 1])
                    self.update_summary_file(ip, hostname, mac, scanned_ports_so_far, merged_vulns)
                    self.save_vulnerability_details(mac, ip, all_details)
                    self._update_vuln_counter()

        # Merge duplicate findings across ports — add port to existing finding
        merged_details = []
        seen_scripts = {}  # script_name -> index in merged_details
        for finding in all_details:
            key = finding.get('script', '')
            if key in seen_scripts:
                # Same vulnerability on another port — append port info
                existing = merged_details[seen_scripts[key]]
                existing_port = existing.get('port', '')
                new_port = finding.get('port', '')
                if new_port and new_port not in existing_port:
                    existing['port'] = f"{existing_port}, {new_port}"
                    existing_svc = existing.get('service', '')
                    new_svc = finding.get('service', '')
                    if new_svc and new_svc not in existing_svc:
                        existing['service'] = f"{existing_svc}, {new_svc}"
            else:
                seen_scripts[key] = len(merged_details)
                merged_details.append(finding)
        all_details = merged_details

        # Enrich findings with threat intelligence (KEV + optional NVD)
        if all_details and self.kev_db.loaded:
            all_details = enrich_findings(all_details, self.kev_db, self.nvd_client)
            kev_count = sum(1 for d in all_details if d.get('kev'))
            if kev_count:
                logger.info(f"{ip}: {kev_count} finding(s) flagged as known exploited (CISA KEV)")

        # Save combined results from all ports that completed
        if ports_succeeded > 0:
            merged_vulns = "; ".join(sorted(all_vulnerabilities)) if all_vulnerabilities else ""
            scanned_ports = ",".join(ports)
            if merged_vulns:
                logger.info(f"All vulnerabilities on {ip}: {merged_vulns}")
            else:
                logger.info(f"No vulnerabilities found on {ip}")
            self.update_summary_file(ip, hostname, mac, scanned_ports, merged_vulns)
            self.save_vulnerability_details(mac, ip, all_details)
            return combined_result
        else:
            logger.warning(f"All ports timed out or failed for {ip}")
            return None

    def execute(self, ip, row, status_key):
        """
        Executes the vulnerability scan for a given IP and row data.
        """
        start_time = time.time()
        logger.lifecycle_start("NmapVulnScanner", ip)
        if not self.nse_available:
            logger.error(f"Skipping vuln scan for {ip} — NSE scripts not available")
            logger.lifecycle_end("NmapVulnScanner", "failed", 0, ip)
            return 'failed'
        self.shared_data.lokiorch_status = "NmapVulnScanner"
        ports = row["Ports"].split(";")
        # Parse service info from netkb for smarter script selection
        services_str = row.get("Services", "")
        try:
            scan_result = self.scan_vulnerabilities(ip, row["Hostnames"], row["MAC Address"], ports)

            if scan_result is not None:
                self.scan_results.append((ip, row["Hostnames"], row["MAC Address"]))
                self.save_results(row["MAC Address"], ip, scan_result)
                status = 'success'
            else:
                status = 'failed'
        except Exception as e:
            logger.error(f"Error during vulnerability scan for {ip}: {e}")
            status = 'failed'
        finally:
            duration = time.time() - start_time
            logger.lifecycle_end("NmapVulnScanner", status, duration, ip)
        return status

    # Regex matching NSE script headers in both multi-line and single-line formats:
    #   "| http-git: "          (multi-line block header)
    #   "|_http-trace: TRACE…"  (single-line result)
    _SCRIPT_RE = re.compile(r'^\|[_ ]?\s*([\w][\w-]*-[\w][\w-]*)\s*:\s*(.*)')

    # Nmap output lines that indicate the script found nothing — not a vulnerability
    _NEGATIVE_RE = re.compile(
        r"Couldn't find any|Couldn't find a file-type"
        r"|not\s+(?:\w+\s+)*vulnerable|NOT VULNERABLE"
        r"|no vulnerable|no issues found|^ERROR(?::|$)"
        r"|Script execution failed|^false$"
        r"|Can't guess domain|not currently available"
        r"|No reply from server|DISABLED"
        r"|Could not negotiate|Failed to receive bytes"
        r"|Couldn't establish connection"
        r"|Connection refused|Connection timed out"
        r"|Failed to connect|Authentication failed"
        r"|bind\.version:",
        re.IGNORECASE)

    def parse_vulnerabilities(self, scan_result):
        """
        Parses Nmap NSE script output to extract findings.

        Two output styles are handled:
        1. Structured vuln blocks (http-vuln-*, smb-vuln-*, etc.):
               | http-vuln-cve2012-1823:
               |   VULNERABLE:
               |     State: VULNERABLE
               |     IDs:  CVE:CVE-2012-1823
           → requires "State: VULNERABLE"; stores CVE IDs or script name.

        2. Informational scripts (http-git, http-enum, http-cookie-flags, etc.):
               | http-git:
               |   10.0.0.1:80/.git/
               |     Potential Git repository found
           → any output lines after the header = a finding; stores script name.

        3. Single-line results:
               |_http-trace: TRACE is enabled
           → positive inline text = a finding; negative text = skip.
        """
        vulnerabilities = set()
        current_script = None
        current_cves = set()
        is_vulnerable = False
        has_output = False
        in_refs = False

        def save_block():
            if not current_script:
                return
            friendly = self._SCRIPT_TITLES.get(current_script, current_script)
            if is_vulnerable:
                # Structured vuln block — use title with CVE if available
                if current_cves:
                    cve_str = ", ".join(sorted(current_cves))
                    vulnerabilities.add(f"{friendly} ({cve_str})")
                else:
                    vulnerabilities.add(friendly)
            elif has_output and '-vuln-' not in current_script:
                # Informational script with output — the output IS the finding
                vulnerabilities.add(friendly)

        for line in scan_result.splitlines():
            m = self._SCRIPT_RE.match(line)
            if m:
                save_block()
                current_script = m.group(1)
                current_cves = set()
                is_vulnerable = False
                has_output = False
                in_refs = False
                # Single-line result: "|_http-trace: TRACE is enabled"
                inline = m.group(2).strip()
                if inline and not self._NEGATIVE_RE.search(inline):
                    has_output = True
                continue

            # Count content lines belonging to current script block
            if current_script and re.match(r'^\|[_ ]?\s', line):
                stripped = re.sub(r'^\|[_ ]?\s*', '', line).strip()
                if stripped and not self._NEGATIVE_RE.search(stripped):
                    has_output = True

            # Stop collecting CVEs once we hit References section
            if re.match(r'^\|?\s+References:', line):
                in_refs = True

            # "State: VULNERABLE" or "State: LIKELY VULNERABLE" confirms a finding
            if re.search(r'State:\s+(LIKELY\s+)?VULNERABLE', line):
                is_vulnerable = True

            # Collect CVE IDs only from IDs line, not from References URLs
            if is_vulnerable and not in_refs:
                for cve in re.findall(r'CVE-\d{4}-\d+', line):
                    current_cves.add(cve)

        save_block()

        return "; ".join(sorted(vulnerabilities))

    def parse_vulnerability_details(self, scan_result):
        """
        Parse structured vulnerability details from nmap NSE script output.
        Returns list of findings with port, service, title, state, CVEs, description.
        """
        findings = []
        current_port = None
        current_service = None

        lines = scan_result.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]

            # Track current port/service
            port_match = re.match(r'^(\d+/\w+)\s+\w+\s+(\S+)', line)
            if port_match:
                current_port = port_match.group(1)
                current_service = port_match.group(2)
                i += 1
                continue

            if 'Host script results:' in line:
                current_port = 'host'
                current_service = None
                i += 1
                continue

            # Script header — matches both "| script:" and "|_script: text"
            script_match = self._SCRIPT_RE.match(line)
            if script_match:
                script_name = script_match.group(1)
                inline_text = script_match.group(2).strip()

                # Single-line result (|_script: text) — no block lines to collect
                if line.startswith('|_') and inline_text:
                    if not self._NEGATIVE_RE.search(inline_text):
                        finding = self._make_info_finding(
                            script_name, inline_text, current_port, current_service)
                        if finding:
                            findings.append(finding)
                    i += 1
                    continue

                # Multi-line block — collect lines until next script or end
                block_lines = []
                i += 1
                while i < len(lines):
                    l = lines[i]
                    if re.match(r'^\d+/\w+\s+\w+', l) or 'Host script results:' in l:
                        break
                    if self._SCRIPT_RE.match(l):
                        break
                    if not l.startswith('|'):
                        break
                    block_lines.append(l)
                    i += 1

                finding = self._parse_vuln_block(script_name, block_lines,
                                                  current_port, current_service)
                if finding:
                    findings.append(finding)
                continue

            i += 1

        return findings

    # Human-readable titles for well-known informational scripts
    _SCRIPT_TITLES = {
        'http-git': 'Git Repository Exposed',
        'http-enum': 'Common Paths Found',
        'http-trace': 'TRACE Method Enabled',
        'http-csrf': 'CSRF Vulnerabilities',
        'http-cookie-flags': 'Insecure Cookie Flags',
        'http-cross-domain-policy': 'Permissive Cross-Domain Policy',
        'http-internal-ip-disclosure': 'Internal IP Disclosure',
        'http-method-tamper': 'HTTP Method Tampering',
        'http-sql-injection': 'SQL Injection',
        'http-dombased-xss': 'DOM-Based XSS',
        'http-stored-xss': 'Stored XSS',
        'http-shellshock': 'Shellshock (CVE-2014-6271)',
        'http-slowloris-check': 'Slowloris DoS Vulnerability',
        'http-fileupload-exploiter': 'File Upload Vulnerability',
        'http-passwd': 'Password File Disclosure',
        'http-phpmyadmin-dir-traversal': 'phpMyAdmin Directory Traversal',
        'http-jsonp-detection': 'JSONP Endpoint Found',
        'http-phpself-xss': 'PHP_SELF XSS',
        # SSL/TLS scripts
        'ssl-enum-ciphers': 'SSL/TLS Cipher Enumeration',
        'ssl-cert': 'SSL Certificate Info',
        'ssl-heartbleed': 'Heartbleed (CVE-2014-0160)',
        'ssl-poodle': 'POODLE (CVE-2014-3566)',
        'ssl-dh-params': 'Weak Diffie-Hellman Parameters',
        'ssl-ccs-injection': 'CCS Injection (CVE-2014-0224)',
        # DNS scripts
        'dns-zone-transfer': 'DNS Zone Transfer',
        'dns-brute': 'DNS Brute Force',
        'dns-cache-snoop': 'DNS Cache Snooping',
        'dns-recursion': 'DNS Recursion Enabled',
        'dns-nsid': 'DNS NSID',
        # SNMP scripts
        'snmp-info': 'SNMP System Info',
        'snmp-brute': 'SNMP Community String Brute Force',
        'snmp-sysdescr': 'SNMP System Description',
        'snmp-netstat': 'SNMP Network Statistics',
        'snmp-processes': 'SNMP Running Processes',
        # Vulners
        'vulners': 'Known Vulnerabilities (Vulners)',
        # Enumeration scripts
        'ftp-anon': 'FTP Anonymous Login',
        'ftp-syst': 'FTP System Info',
        'ssh2-enum-algos': 'SSH Algorithms',
        'ssh-hostkey': 'SSH Host Key',
        'telnet-ntlm-info': 'Telnet NTLM Info',
        'telnet-encryption': 'Telnet Encryption',
        'smtp-enum-users': 'SMTP User Enumeration',
        'smtp-ntlm-info': 'SMTP NTLM Info',
        'finger': 'Finger User Enumeration',
        'pop3-capabilities': 'POP3 Capabilities',
        'pop3-ntlm-info': 'POP3 NTLM Info',
        'rpcinfo': 'RPC Services',
        'imap-capabilities': 'IMAP Capabilities',
        'imap-ntlm-info': 'IMAP NTLM Info',
        'ldap-rootdse': 'LDAP Root DSE',
        'ldap-search': 'LDAP Search',
        'smb-enum-shares': 'SMB Shares',
        'smb-enum-users': 'SMB Users',
        'smb-security-mode': 'SMB Security Mode',
        'smb-protocols': 'SMB Protocol Versions',
        'smb2-security-mode': 'SMB2 Signing Mode',
        'afp-serverinfo': 'AFP Server Info',
        'afp-showmount': 'AFP Shared Volumes',
        'rtsp-methods': 'RTSP Methods',
        'cups-info': 'CUPS Printer Info',
        'cups-queue-info': 'CUPS Print Queues',
        'rsync-list-modules': 'Rsync Modules',
        'rmi-dumpregistry': 'Java RMI Registry',
        'ms-sql-info': 'MS-SQL Server Info',
        'ms-sql-ntlm-info': 'MS-SQL NTLM Info',
        'oracle-tns-version': 'Oracle TNS Version',
        'mqtt-subscribe': 'MQTT Topics',
        'nfs-showmount': 'NFS Exports',
        'iscsi-info': 'iSCSI Targets',
        'mysql-info': 'MySQL Server Info',
        'rdp-enum-encryption': 'RDP Encryption Level',
        'rdp-ntlm-info': 'RDP NTLM Info',
        'sip-methods': 'SIP Methods',
        'xmpp-info': 'XMPP Server Info',
        'amqp-info': 'AMQP Server Info',
        'vnc-info': 'VNC Server Info',
        'realvnc-auth-bypass': 'RealVNC Auth Bypass',
        'redis-info': 'Redis Server Info',
        'memcached-info': 'Memcached Server Info',
        'mongodb-info': 'MongoDB Server Info',
        'mongodb-databases': 'MongoDB Databases',
        # HTTP enumeration
        'http-wordpress-enum': 'WordPress Enumeration',
        'http-drupal-enum': 'Drupal Enumeration',
        'http-auth-finder': 'Authentication Pages Found',
        'http-robots.txt': 'Robots.txt Entries',
    }

    # Nmap noise lines to skip when building descriptions
    _NOISE_RE = re.compile(
        r'^Spidering limited to:|^Couldn\'t find|^No output from'
        r'|^Did not find any|^Server does not',
        re.IGNORECASE)

    def _make_info_finding(self, script_name, text, port, service):
        """Create a finding dict for a single-line informational result."""
        return {
            'port': port or '',
            'service': service or '',
            'script': script_name,
            'title': self._SCRIPT_TITLES.get(script_name, script_name),
            'state': 'FOUND',
            'cves': [],
            'risk': 'Informational',
            'description': text,
            'disclosure_date': '',
            'references': []
        }

    def _parse_vuln_block(self, script_name, block_lines, port, service):
        """Parse a single NSE script block. Returns a finding dict or None.

        Handles two formats:
        1. Structured vuln blocks with State:/IDs:/Risk factor: fields
        2. Informational scripts that just list findings as text lines
        """
        state = ''
        title = ''
        cves = []
        risk = ''
        desc_lines = []
        disclosure = ''
        refs = []
        in_refs = False
        got_title = False
        info_lines = []

        for line in block_lines:
            # Strip the leading |/|_ and whitespace
            stripped = re.sub(r'^\|[_ ]?\s*', '', line).strip()

            # State line
            state_match = re.search(r'State:\s+((?:LIKELY\s+)?VULNERABLE)', line)
            if state_match:
                state = state_match.group(1)
                in_refs = False
                continue

            # Skip the VULNERABLE: header line itself
            if stripped in ('VULNERABLE:', 'LIKELY VULNERABLE:'):
                continue

            # Skip NOT VULNERABLE
            if 'NOT VULNERABLE' in stripped:
                return None

            # Skip negative/noise lines for informational scripts
            if self._NEGATIVE_RE.search(stripped):
                continue

            # References section — must be checked before CVE collection
            # to avoid grabbing CVE IDs from reference URLs
            if stripped == 'References:':
                in_refs = True
                continue

            if in_refs and ('http://' in stripped or 'https://' in stripped):
                refs.append(stripped)
                continue

            # CVE IDs (only from IDs line, not from References URLs)
            if not in_refs:
                found_cves = re.findall(r'CVE-\d{4}-\d+', line)
                if found_cves:
                    cves.extend(found_cves)
                    continue

            # IDs line without CVE
            if stripped.startswith('IDs:'):
                continue

            # Risk factor
            risk_match = re.match(r'Risk factor:\s*(.+)', stripped)
            if risk_match:
                risk = risk_match.group(1).strip()
                in_refs = False
                continue

            # Disclosure date
            date_match = re.match(r'Disclosure date:\s*(.+)', stripped)
            if date_match:
                disclosure = date_match.group(1).strip()
                in_refs = False
                continue

            # Skip State/property lines we already handled
            if any(stripped.startswith(kw) for kw in ('State:', 'IDs:', 'Risk factor:',
                                                       'Disclosure date:', 'References:')):
                continue

            # Collect non-noise lines for informational output
            if stripped and not self._NOISE_RE.match(stripped):
                info_lines.append(stripped)

            # Title — first meaningful line
            if not got_title and stripped:
                title = stripped
                got_title = True
                continue

            # Description — lines between title and structured fields
            if got_title and not in_refs and stripped:
                desc_lines.append(stripped)

        # Structured vuln block — require State: VULNERABLE
        if state:
            return {
                'port': port or '',
                'service': service or '',
                'script': script_name,
                'title': self._SCRIPT_TITLES.get(script_name, title),
                'state': state,
                'cves': list(set(cves)),
                'risk': risk,
                'description': ' '.join(desc_lines),
                'disclosure_date': disclosure,
                'references': refs
            }

        # Informational script — any output = a finding (skip *-vuln-* without state)
        if info_lines and '-vuln-' not in script_name:
            return {
                'port': port or '',
                'service': service or '',
                'script': script_name,
                'title': self._SCRIPT_TITLES.get(script_name, script_name),
                'state': 'FOUND',
                'cves': list(set(cves)),
                'risk': risk or 'Informational',
                'description': ' '.join(info_lines[:10]),
                'disclosure_date': '',
                'references': refs
            }

        return None

    def save_vulnerability_details(self, mac_address, ip, details):
        """Save structured vulnerability details as JSON."""
        try:
            sanitized_mac = mac_address.replace(":", "")
            result_dir = self.shared_data.vulnerabilities_dir
            os.makedirs(result_dir, exist_ok=True)
            json_file = os.path.join(result_dir, f"{sanitized_mac}_{ip}_vuln_details.json")
            with open(json_file, 'w') as f:
                json.dump(details, f, indent=2)
            if details:
                logger.debug(f"Vulnerability details saved to {json_file}")
        except Exception as e:
            logger.error(f"Error saving vulnerability details for {ip}: {e}")

    def save_results(self, mac_address, ip, scan_result):
        """
        Saves the detailed scan results to a file.
        """
        try:
            sanitized_mac_address = mac_address.replace(":", "")
            result_dir = self.shared_data.vulnerabilities_dir
            os.makedirs(result_dir, exist_ok=True)
            result_file = os.path.join(result_dir, f"{sanitized_mac_address}_{ip}_vuln_scan.txt")

            # Open the file in write mode to clear its contents if it exists, then close it
            if os.path.exists(result_file):
                open(result_file, 'w').close()

            # Write the new scan result to the file
            with open(result_file, 'w') as file:
                file.write(scan_result)

            logger.debug(f"Results saved to {result_file}")
        except Exception as e:
            logger.error(f"Error saving scan results for {ip}: {e}")


    def save_summary(self):
        """
        Saves a summary of all scanned vulnerabilities to a final summary file.
        """
        try:
            final_summary_file = os.path.join(self.shared_data.vulnerabilities_dir, "final_vulnerability_summary.csv")

            # Read existing data
            rows = []
            if os.path.exists(self.summary_file):
                with open(self.summary_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)

            # Group by IP, Hostname, MAC Address and combine vulnerabilities
            grouped = {}
            for row in rows:
                key = (row.get("IP", ""), row.get("Hostname", ""), row.get("MAC Address", ""))
                if key not in grouped:
                    grouped[key] = set()
                vulns = row.get("Vulnerabilities", "")
                if vulns:
                    for v in vulns.split("; "):
                        if v.strip():
                            grouped[key].add(v.strip())

            # Write summary
            with open(final_summary_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Hostname", "MAC Address", "Vulnerabilities"])
                for (ip, hostname, mac), vulns in grouped.items():
                    writer.writerow([ip, hostname, mac, "; ".join(vulns)])

            logger.debug(f"Summary saved to {final_summary_file}")
        except Exception as e:
            logger.error(f"Error saving summary: {e}")

if __name__ == "__main__":
    shared_data = SharedData()
    try:
        nmap_vuln_scanner = NmapVulnScanner(shared_data)
        logger.info("Starting vulnerability scans...")

        # Load the netkbfile and get the IPs to scan
        ips_to_scan = shared_data.read_data()  # Use your existing method to read the data

        # Execute the scan on each IP with concurrency
        total = len(ips_to_scan)
        completed = 0
        futures = []
        with ThreadPoolExecutor(max_workers=2) as executor:  # Adjust the number of workers for RPi Zero
            for row in ips_to_scan:
                if row["Alive"] == '1':  # Check if the host is alive
                    ip = row["IPs"]
                    futures.append(executor.submit(nmap_vuln_scanner.execute, ip, row, b_status))

            # Use timeout on as_completed to prevent infinite blocking
            for future in as_completed(futures, timeout=1800):  # 30 minute total timeout
                try:
                    future.result(timeout=600)  # 10 minute timeout per scan
                except FuturesTimeoutError:
                    logger.warning("Scan timed out")
                except Exception as e:
                    logger.error(f"Scan error: {e}")
                completed += 1
                logger.info(f"Scanning vulnerabilities... {completed}/{len(futures)}")

        nmap_vuln_scanner.save_summary()
        logger.info(f"Total scans performed: {len(nmap_vuln_scanner.scan_results)}")
        exit(len(nmap_vuln_scanner.scan_results))
    except FuturesTimeoutError:
        logger.error("Overall vulnerability scanning timed out after 30 minutes")
    except Exception as e:
        logger.error(f"Error: {e}")
