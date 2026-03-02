#shared.py
# Description:
# Shared resources and data for Bjorn on WiFi Pineapple Pager.
# Modified from original to use pagerctl instead of PIL/EPD.
#
# Changes from original:
# - Removed PIL and EPD dependencies
# - Updated paths for Pager filesystem
# - Font paths stored instead of PIL fonts
# - Image paths stored instead of PIL images
# - Display settings for 480x222 RGB565 LCD

import os
import re
import json
import importlib
import random
import time
import csv
import logging
import subprocess
from logger import Logger

logger = Logger(name="shared.py", level=logging.INFO)

class SharedData:
    """Shared data between the different modules."""
    def __init__(self):
        self.initialize_paths()
        self.status_list = []
        self.last_comment_time = time.time()
        self.default_config = self.get_default_config()
        self.config = self.default_config.copy()
        self.load_config()
        self.update_mac_blacklist()
        self.setup_environment()
        self.initialize_variables()
        self.create_livestatusfile()
        self.animation_mode = "random"
        self._frame_index = 0
        self._last_seq_status = None
        self.load_fonts()
        self.load_images()
        self.load_theme()

    def initialize_paths(self):
        """Initialize the paths used by the application."""
        # Base directory is where this script is located
        self.currentdir = os.path.dirname(os.path.abspath(__file__))

        # Directories under currentdir (payload folder)
        self.configdir = os.path.join(self.currentdir, 'config')
        self.actions_dir = os.path.join(self.currentdir, 'actions')
        self.resourcesdir = os.path.join(self.currentdir, 'resources')

        # Data directories on SD card for persistence
        # Using /mmc/root/loot/bjorn for data that needs to survive reboots
        self.datadir = '/mmc/root/loot/bjorn'
        self.logsdir = os.path.join(self.datadir, 'logs')
        self.output_dir = os.path.join(self.datadir, 'output')
        self.input_dir = os.path.join(self.datadir, 'input')

        # Control file for inter-process communication (webapp <-> Bjorn)
        self.orchestrator_control_file = os.path.join(self.datadir, '.orchestrator_control')

        # Create data directories if they don't exist
        for d in [self.datadir, self.logsdir, self.output_dir, self.input_dir]:
            os.makedirs(d, exist_ok=True)

        # Directories under output_dir
        self.crackedpwddir = os.path.join(self.output_dir, 'crackedpwd')
        self.datastolendir = os.path.join(self.output_dir, 'data_stolen')
        self.zombiesdir = os.path.join(self.output_dir, 'zombies')
        self.vulnerabilities_dir = os.path.join(self.output_dir, 'vulnerabilities')
        self.scan_results_dir = os.path.join(self.output_dir, "scan_results")

        # Create output subdirectories
        for d in [self.crackedpwddir, self.datastolendir, self.zombiesdir,
                  self.vulnerabilities_dir, self.scan_results_dir]:
            os.makedirs(d, exist_ok=True)

        # Directories under resourcesdir
        self.picdir = os.path.join(self.resourcesdir, 'images')
        self.fontdir = os.path.join(self.resourcesdir, 'fonts')
        self.commentsdir = os.path.join(self.resourcesdir, 'comments')

        # Directories under picdir
        self.statuspicdir = os.path.join(self.picdir, 'status')
        self.staticpicdir = os.path.join(self.picdir, 'static')

        # Dictionary files are bundled in resources/dictionary/
        self.dictionarydir = os.path.join(self.resourcesdir, "dictionary")

        # Backup directories (not used on Pager, but keep for compatibility)
        self.backupbasedir = os.path.join(self.datadir, 'backup')
        self.backupdir = os.path.join(self.backupbasedir, 'backups')
        self.upload_dir = os.path.join(self.backupbasedir, 'uploads')

        # Web directory (static files in payload folder)
        self.webdir = os.path.join(self.currentdir, 'web')

        # Files
        self.shared_config_json = os.path.join(self.configdir, 'shared_config.json')
        self.actions_file = os.path.join(self.configdir, 'actions.json')
        self.commentsfile = os.path.join(self.commentsdir, 'comments.json')
        self.netkbfile = os.path.join(self.datadir, "netkb.csv")
        self.livestatusfile = os.path.join(self.datadir, 'livestatus.csv')
        self.vuln_summary_file = os.path.join(self.vulnerabilities_dir, 'vulnerability_summary.csv')
        self.vuln_scan_progress_file = os.path.join(self.vulnerabilities_dir, 'scan_progress.json')
        self.usersfile = os.path.join(self.dictionarydir, "users.txt")
        self.passwordsfile = os.path.join(self.dictionarydir, "passwords.txt")
        self.sshfile = os.path.join(self.crackedpwddir, 'ssh.csv')
        self.smbfile = os.path.join(self.crackedpwddir, "smb.csv")
        self.telnetfile = os.path.join(self.crackedpwddir, "telnet.csv")
        self.ftpfile = os.path.join(self.crackedpwddir, "ftp.csv")
        self.sqlfile = os.path.join(self.crackedpwddir, "sql.csv")
        self.rdpfile = os.path.join(self.crackedpwddir, "rdp.csv")
        self.webconsolelog = os.path.join(self.logsdir, 'temp_log.txt')

    def get_default_config(self):
        """Pager-specific default configuration."""
        return {
            "__title_attacks__": "Attack Settings",
            "manual_mode": True,
            "clear_hosts_on_startup": False,
            "brute_force_running": True,
            "file_steal_running": True,
            "scan_vuln_running": True,
            "attack_order": "spread",

            "__title_retry__": "Retry Settings",
            "retry_success_actions": False,
            "retry_failed_actions": True,
            "failed_retry_delay": 600,
            "success_retry_delay": 900,

            "__title_network__": "Network & Scanning",
            "scan_interval": 300,
            "scan_network_prefix": 24,
            "nmap_scan_aggressivity": "-T2",
            "vuln_scan_timeout": 120,
            "portstart": 1,
            "portend": 2,
            "portlist": [20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 137, 139, 143, 161, 162, 389, 443, 445, 512, 513, 514, 587, 636, 993, 995, 1080, 1433, 1521, 2049, 3306, 3389, 5000, 5001, 5432, 5900, 8080, 8443, 9090, 10000],
            "blacklistcheck": True,
            "blacklist_gateway": True,
            "mac_scan_blacklist": [],
            "ip_scan_blacklist": [],

            "__title_stealing__": "File Stealing",
            "steal_file_names": ["ssh.csv", "hack.txt"],
            "steal_file_extensions": [".bjorn", ".hack", ".flag"],
            "steal_max_depth": 3,
            "steal_max_files": 500,

            "__title_timing__": "Delay Settings",
            "startup_delay": 5,
            "web_delay": 2,
            "comment_delaymin": 15,
            "comment_delaymax": 30,
            "image_display_delaymin": 2,
            "image_display_delaymax": 8,
            "timewait_smb": 0,
            "timewait_ssh": 0,
            "timewait_telnet": 0,
            "timewait_ftp": 0,
            "timewait_sql": 0,
            "timewait_rdp": 0,

            "__title_performance__": "Performance",
            "worker_threads": 5,
            "max_failed_retries": 3,
            "bruteforce_queue_timeout": 600,
            "displaying_csv": True,

            "__title_logging__": "Logging",
            "log_debug": False,
            "log_info": True,
            "log_warning": True,
            "log_error": True,
            "log_critical": True,

            "__title_display__": "Display",
            "screen_brightness": 80,
            "screen_dim_brightness": 25,
            "screen_dim_timeout": 60,
            "screen_rotation": 270,

            "__title_theme__": "Theme",
            "theme": "bjorn",
            "override_theme_delays": False,
            "override_theme_comment_delays": False,
        }

    def update_mac_blacklist(self):
        """Update MAC blacklist and build effective IP blacklist.

        The persisted ip_scan_blacklist in config is user-managed only.
        Device IPs and gateway are added at runtime and not saved to config.
        """
        # Update MAC blacklist
        mac_address = self.get_device_mac()
        if mac_address:
            if 'mac_scan_blacklist' not in self.config:
                self.config['mac_scan_blacklist'] = []

            if mac_address not in self.config['mac_scan_blacklist']:
                self.config['mac_scan_blacklist'].append(mac_address)
                logger.info(f"Added local MAC address {mac_address} to blacklist")
        else:
            logger.warning("Could not add local MAC to blacklist: MAC address not found")

        # Build effective IP blacklist: user's manual list + auto-detected device IPs + gateway
        effective = list(self.config.get('ip_scan_blacklist', []))

        # Auto-detect this device's IPs (runtime only, not persisted)
        device_ips = self.get_device_ips()
        for ip in device_ips:
            if ip not in effective:
                effective.append(ip)
                logger.info(f"Auto-blacklisted device IP {ip}")

        # Conditionally add gateway based on toggle (runtime only, not persisted)
        if self.config.get('blacklist_gateway', True):
            gateway_ip = self.get_gateway_ip()
            if gateway_ip:
                if gateway_ip not in effective:
                    effective.append(gateway_ip)
                    logger.info(f"Auto-blacklisted gateway IP {gateway_ip}")
            else:
                logger.warning("Could not detect gateway IP for blacklist")
        else:
            logger.info("Gateway blacklisting disabled by config")

        # Set effective blacklist (this is what scanning.py snapshots at init)
        self.ip_scan_blacklist = effective
        logger.info(f"Effective IP blacklist: {effective}")

    def get_gateway_ip(self):
        """Get the default gateway IP address."""
        try:
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                    capture_output=True, text=True, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                parts = result.stdout.strip().split()
                if 'via' in parts:
                    return parts[parts.index('via') + 1]
            return None
        except Exception as e:
            logger.error(f"Error getting gateway IP: {e}")
            return None

    def get_device_mac(self):
        """Get the MAC address of the primary network interface."""
        try:
            # Try wlan0 first (WiFi Pineapple primary interface)
            for iface in ['wlan0', 'wlan1', 'eth0', 'br-lan']:
                path = f'/sys/class/net/{iface}/address'
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        mac = f.read().strip().lower()
                        if mac and mac != '00:00:00:00:00:00':
                            return mac
            logger.warning("Could not find MAC address for any interface")
            return None
        except Exception as e:
            logger.error(f"Error getting device MAC address: {e}")
            return None

    def get_device_ips(self):
        """Get all IP addresses of this device."""
        ips = []
        try:
            # Use ip addr to get all IPs
            result = subprocess.run(['ip', '-4', 'addr', 'show'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                import re
                # Match inet X.X.X.X
                for match in re.finditer(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout):
                    ip = match.group(1)
                    # Skip localhost
                    if not ip.startswith('127.'):
                        ips.append(ip)
            if ips:
                logger.debug(f"Found device IPs: {ips}")
            return ips
        except Exception as e:
            logger.error(f"Error getting device IPs: {e}")
            return []

    @staticmethod
    def get_battery_level():
        """Get battery percentage (0-100) or None if unavailable."""
        import glob as _glob

        # Method 1: Standard Linux sysfs interface
        try:
            for bat_path in _glob.glob('/sys/class/power_supply/*/capacity'):
                with open(bat_path, 'r') as f:
                    return int(f.read().strip())
        except Exception:
            pass

        # Method 2: ubus (OpenWRT/Pineapple)
        try:
            result = subprocess.run(
                ['ubus', 'call', 'battery', 'info'],
                capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if 'percent' in data:
                    return int(data['percent'])
                if 'capacity' in data:
                    return int(data['capacity'])
        except Exception:
            pass

        # Method 3: /tmp files (some devices write battery here)
        try:
            for path in ['/tmp/battery', '/tmp/battery_percent', '/var/battery']:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        return int(f.read().strip())
        except Exception:
            pass

        # Method 4: Pineapple-specific platform paths
        try:
            for path in ['/sys/devices/platform/battery/capacity',
                         '/sys/devices/platform/axp20x-battery-power-supply/capacity']:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        return int(f.read().strip())
        except Exception:
            pass

        return None

    @staticmethod
    def get_battery_charging():
        """Check if battery is charging. Returns True/False/None."""
        import glob as _glob

        try:
            for status_path in _glob.glob('/sys/class/power_supply/*/status'):
                with open(status_path, 'r') as f:
                    status = f.read().strip().lower()
                    return status in ('charging', 'full')
        except Exception:
            pass

        return None

    def setup_environment(self):
        """Setup the environment with the necessary directories and files."""
        self.save_config()
        self.generate_actions_json()
        self.delete_webconsolelog()
        self.initialize_csv()
        self.initialize_display()

    def initialize_display(self):
        """Initialize display settings for Pager LCD."""
        try:
            logger.info("Initializing Pager display settings...")
            # Set dimensions based on screen_rotation config
            rotation = self.config.get('screen_rotation', 270)
            if rotation == 270:
                # Landscape mode (default)
                self.width = 480
                self.height = 222
            else:
                # Portrait mode
                self.width = 222
                self.height = 480
            self.screen_rotation = rotation
            self.screen_reversed = False
            self.web_screen_reversed = False
            logger.debug(f"Display defaults set: {self.width}x{self.height} (rotation={rotation})")
        except Exception as e:
            logger.error(f"Error initializing display settings: {e}")
            raise

    def initialize_variables(self):
        """Initialize the variables."""
        self.should_exit = False
        self.display_should_exit = False
        self._orchestrator_should_exit = False  # Local cache, use property for IPC
        self.webapp_should_exit = False
        self.manual_attack_running = False
        self.manual_attack_name = None
        self.bjorn_instance = None
        self.wifichanged = False
        self.bluetooth_active = False
        self.wifi_connected = False
        self.pan_connected = False
        self.usb_active = False
        self.bjornsay = "Hacking away..."
        self.bjornorch_status = "IDLE"
        self.bjornstatustext = "IDLE"
        self.bjornstatustext2 = "Awakening..."

        # Scale factors for positioning (relative to original 122x250 display)
        self.scale_factor_x = self.width / 122
        self.scale_factor_y = self.height / 250

        self.text_frame_top = int(88 * self.scale_factor_y)
        self.text_frame_bottom = int(159 * self.scale_factor_y)
        self.y_text = self.text_frame_top + 2

        # Stats
        self.targetnbr = 0
        self.portnbr = 0
        self.vulnnbr = 0
        self.crednbr = 0
        self.datanbr = 0
        self.zombiesnbr = 0
        self.coinnbr = 0
        self.levelnbr = 0
        self.networkkbnbr = 0
        self.attacksnbr = 0
        self.show_first_image = True

        # Battery state
        self.battery_level = None
        self.battery_charging = None

        # Current image for animation
        self.imagegen = None
        self.current_image_path = None

    @property
    def orchestrator_should_exit(self):
        """Read orchestrator exit flag from control file (for IPC between webapp and Bjorn)."""
        try:
            if os.path.exists(self.orchestrator_control_file):
                with open(self.orchestrator_control_file, 'r') as f:
                    content = f.read().strip()
                    return content == 'stop'
            return False  # Default: orchestrator should run
        except Exception:
            return self._orchestrator_should_exit  # Fallback to local cache

    @orchestrator_should_exit.setter
    def orchestrator_should_exit(self, value):
        """Write orchestrator exit flag to control file (for IPC between webapp and Bjorn)."""
        self._orchestrator_should_exit = value
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.orchestrator_control_file), exist_ok=True)
            with open(self.orchestrator_control_file, 'w') as f:
                f.write('stop' if value else 'run')
        except Exception as e:
            logger.error(f"Error writing orchestrator control file: {e}")

    def delete_webconsolelog(self):
        """Delete the web console log file."""
        try:
            if os.path.exists(self.webconsolelog):
                os.remove(self.webconsolelog)
                logger.info(f"Deleted web console log file at {self.webconsolelog}")
            else:
                logger.info(f"Web console log file not found at {self.webconsolelog}")
        except OSError as e:
            logger.error(f"OS error occurred while deleting web console log file: {e}")
        except Exception as e:
            logger.error(f"Unexpected error occurred while deleting web console log file: {e}")

    def record_zombie(self, mac_address, ip_address):
        """Record a compromised host (zombie) - only counts each host once."""
        try:
            # Use MAC_IP as unique identifier for the host
            zombie_id = f"{mac_address}_{ip_address}".replace(":", "-")
            zombie_file = os.path.join(self.zombiesdir, zombie_id)

            # Only create if it doesn't exist (avoid counting same host multiple times)
            if not os.path.exists(zombie_file):
                with open(zombie_file, 'w') as f:
                    f.write(f"{mac_address},{ip_address}\n")
                logger.debug(f"Recorded new zombie: {mac_address} ({ip_address})")
                return True  # New zombie recorded
            return False  # Already recorded
        except Exception as e:
            logger.error(f"Error recording zombie: {e}")
            return False

    def create_livestatusfile(self):
        """Create the live status file."""
        try:
            if not os.path.exists(self.livestatusfile):
                with open(self.livestatusfile, 'w', newline='') as csvfile:
                    csvwriter = csv.writer(csvfile)
                    csvwriter.writerow(['Total Open Ports', 'Alive Hosts Count', 'All Known Hosts Count', 'Vulnerabilities Count'])
                    csvwriter.writerow([0, 0, 0, 0])
                logger.info(f"Created live status file at {self.livestatusfile}")
            else:
                logger.info(f"Live status file already exists at {self.livestatusfile}")
        except OSError as e:
            logger.error(f"OS error occurred while creating live status file: {e}")
        except Exception as e:
            logger.error(f"Unexpected error occurred while creating live status file: {e}")

    def generate_actions_json(self):
        """Generate the actions JSON file."""
        actions_dir = self.actions_dir
        actions_config = []
        try:
            for filename in os.listdir(actions_dir):
                if filename.endswith('.py') and filename != '__init__.py':
                    module_name = filename[:-3]
                    try:
                        module = importlib.import_module(f'actions.{module_name}')
                        b_class = getattr(module, 'b_class')
                        b_status = getattr(module, 'b_status')
                        b_port = getattr(module, 'b_port', None)
                        b_parent = getattr(module, 'b_parent', None)
                        actions_config.append({
                            "b_module": module_name,
                            "b_class": b_class,
                            "b_port": b_port,
                            "b_status": b_status,
                            "b_parent": b_parent
                        })
                        self.status_list.append(b_class)
                    except AttributeError as e:
                        logger.error(f"Module {module_name} is missing required attributes: {e}")
                    except ImportError as e:
                        logger.error(f"Error importing module {module_name}: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error while processing module {module_name}: {e}")

            try:
                os.makedirs(os.path.dirname(self.actions_file), exist_ok=True)
                with open(self.actions_file, 'w') as file:
                    json.dump(actions_config, file, indent=4)
            except IOError as e:
                logger.error(f"Error writing to file {self.actions_file}: {e}")
            except Exception as e:
                logger.error(f"Unexpected error while writing to file {self.actions_file}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in generate_actions_json: {e}")

    def initialize_csv(self):
        """Initialize the network knowledge base CSV file with headers if it doesn't exist."""
        try:
            # Get action names for headers
            action_names = []
            try:
                with open(self.actions_file, 'r') as file:
                    actions = json.load(file)
                action_names = [action["b_class"] for action in actions if "b_class" in action]
            except FileNotFoundError as e:
                logger.error(f"Actions file not found: {e}")
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON from actions file: {e}")
            except Exception as e:
                logger.error(f"Unexpected error reading actions file: {e}")

            headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"] + action_names

            # Only create the file if it doesn't exist - never auto-clear
            if not os.path.exists(self.netkbfile):
                try:
                    with open(self.netkbfile, 'w', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow(headers)
                    logger.info(f"Network knowledge base CSV file created at {self.netkbfile}")
                except IOError as e:
                    logger.error(f"Error writing to netkbfile: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error while writing to netkbfile: {e}")
            else:
                logger.debug(f"Network knowledge base CSV file already exists at {self.netkbfile}")
        except Exception as e:
            logger.error(f"Unexpected error in initialize_csv: {e}")

    @staticmethod
    def _expand_port_list(raw):
        """Expand a port list that may contain ranges like '1-1024' or ints."""
        ports = []
        for item in raw:
            s = str(item).strip()
            if '-' in s:
                parts = s.split('-', 1)
                try:
                    lo, hi = int(parts[0]), int(parts[1])
                    ports.extend(range(lo, hi + 1))
                except ValueError:
                    pass
            else:
                try:
                    ports.append(int(s))
                except ValueError:
                    pass
        return ports

    def _apply_log_levels(self):
        """Apply log_debug/info/warning/error/critical toggles to all loggers."""
        import logging as _logging
        from logger import Logger as BjornLogger
        level_map = [
            ('log_debug', _logging.DEBUG),
            ('log_info', _logging.INFO),
            ('log_warning', _logging.WARNING),
            ('log_error', _logging.ERROR),
            ('log_critical', _logging.CRITICAL),
        ]
        # Find the lowest enabled level
        min_level = _logging.CRITICAL + 1
        for key, level in level_map:
            if getattr(self, key, True):
                min_level = min(min_level, level)
        if min_level > _logging.CRITICAL:
            min_level = _logging.INFO  # fallback
        # Set class-level default for future Logger instances
        BjornLogger._configured_level = min_level
        # Update all existing loggers
        for name, log in _logging.Logger.manager.loggerDict.items():
            if isinstance(log, _logging.Logger):
                log.setLevel(min_level)
                for handler in log.handlers:
                    handler.setLevel(min_level)

    def load_config(self):
        """Load the configuration from the shared configuration JSON file."""
        try:
            logger.info("Loading configuration...")
            if os.path.exists(self.shared_config_json):
                with open(self.shared_config_json, 'r') as f:
                    config = json.load(f)
                    self.config.update(config)
                    for key, value in self.config.items():
                        setattr(self, key, value)
                # Expand port ranges (e.g. "1-1024") into individual port numbers
                if hasattr(self, 'portlist') and isinstance(self.portlist, list):
                    self.portlist = self._expand_port_list(self.portlist)
                self._apply_log_levels()
                # Rebuild effective IP blacklist (load_config overwrites it with raw config value)
                self.update_mac_blacklist()
            else:
                logger.warning("Configuration file not found, creating new one with default values...")
                self.save_config()
                self.load_config()
                time.sleep(1)
        except FileNotFoundError:
            logger.error("Error loading configuration: File not found.")
            self.save_config()

    def save_config(self):
        """Save the configuration to the shared configuration JSON file."""
        logger.info("Saving configuration...")
        try:
            if not os.path.exists(self.configdir):
                os.makedirs(self.configdir)
                logger.info(f"Created configuration directory at {self.configdir}")
            try:
                with open(self.shared_config_json, 'w') as f:
                    json.dump(self.config, f, indent=4)
                logger.info(f"Configuration saved to {self.shared_config_json}")
            except IOError as e:
                logger.error(f"Error writing to configuration file: {e}")
            except Exception as e:
                logger.error(f"Unexpected error while writing to configuration file: {e}")
        except OSError as e:
            logger.error(f"OS error while creating configuration directory: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in save_config: {e}")

    def load_fonts(self):
        """Load font paths (not PIL fonts - display.py will use pagerctl)."""
        try:
            logger.info("Loading font paths...")
            # Store font paths instead of PIL font objects
            self.font_arial_path = os.path.join(self.fontdir, 'Arial.ttf')
            self.font_viking_path = os.path.join(self.fontdir, 'Viking.TTF')
            self.font_cartoon_path = os.path.join(self.fontdir, 'Cartoon.ttf')
            self.font_creamy_path = os.path.join(self.fontdir, 'Creamy.ttf')

            # Font sizes for different uses
            self.font_size_small = 12
            self.font_size_medium = 16
            self.font_size_large = 24
            self.font_size_title = 32

            # Verify fonts exist
            for font_path in [self.font_arial_path, self.font_viking_path]:
                if not os.path.exists(font_path):
                    logger.warning(f"Font not found: {font_path}")

        except Exception as e:
            logger.error(f"Error loading font paths: {e}")
            raise

    @staticmethod
    def _find_image(directory, name):
        """Find an image file, preferring .png over .bmp."""
        for ext in ('.png', '.bmp'):
            path = os.path.join(directory, f'{name}{ext}')
            if os.path.isfile(path):
                return path
        return None

    @staticmethod
    def _is_image(filename):
        """Check if a filename is a supported image."""
        return filename.endswith('.bmp') or filename.endswith('.png')


    def _show_loading_screen(self, message="Loading..."):
        """Show a loading message on the pager display during startup."""
        try:
            from pagerctl import Pager
            pager = Pager()
            pager.init()
            pager.set_rotation(270)
            bg = self.theme_bg_color
            txt = self.theme_text_color
            bg_color = pager.rgb(bg[0], bg[1], bg[2])
            txt_color = pager.rgb(txt[0], txt[1], txt[2])
            pager.clear(bg_color)
            # Show theme title
            if hasattr(self, 'font_viking_path') and self.font_viking_path:
                pager.draw_ttf_centered(80, self.display_name, txt_color, self.font_viking_path, 28.0)
            # Show loading message
            font_path = self.font_arial_path if hasattr(self, 'font_arial_path') else ''
            if font_path:
                pager.draw_ttf_centered(180, message, txt_color, font_path, 18.0)
            else:
                pager.draw_text_centered(180, message, txt_color, 2)
            pager.flip()
            pager.cleanup()
        except Exception as e:
            logger.debug(f"Could not show loading screen: {e}")


    def load_images(self):
        """Load image paths (not PIL images - display.py will use pagerctl)."""
        try:
            logger.info("Loading image paths...")

            # Store image paths instead of PIL image objects
            self.bjornstatusimage_path = None

            # Static image paths
            self.static_images = {}
            static_names = ['target', 'port', 'vuln', 'cred', 'zombie', 'data',
                          'frise', 'gold', 'level', 'networkkb', 'attacks',
                          'battery']

            for name in static_names:
                path = self._find_image(self.staticpicdir, name)
                if path:
                    self.static_images[name] = path
                else:
                    logger.warning(f"Static image not found: {name}")

            # Load status image paths from actions
            self.status_images = {}
            try:
                if os.path.exists(self.actions_file):
                    with open(self.actions_file, 'r') as f:
                        actions = json.load(f)
                        for action in actions:
                            b_class = action.get('b_class')
                            if b_class:
                                status_dir = os.path.join(self.statuspicdir, b_class)
                                image_path = self._find_image(status_dir, b_class)
                                if image_path:
                                    self.status_images[b_class] = image_path
                                    logger.debug(f"Found status image for {b_class}")
            except Exception as e:
                logger.error(f"Error loading status image paths: {e}")

            # Load image series paths for animations
            self.image_series = {}
            for status in self.status_list:
                self.image_series[status] = []
                status_dir = os.path.join(self.statuspicdir, status)
                if os.path.isdir(status_dir):
                    for image_name in sorted(os.listdir(status_dir)):
                        if self._is_image(image_name) and re.search(r'\d', image_name):
                            image_path = os.path.join(status_dir, image_name)
                            self.image_series[status].append(image_path)
                    logger.debug(f"Found {len(self.image_series[status])} animation frames for {status}")

            # Calculate character position (center-bottom of screen)
            # Original bjorn image was about 70x90 pixels
            char_width = int(70 * self.scale_factor_x)
            char_height = int(90 * self.scale_factor_y)
            self.x_center1 = (self.width - char_width) // 2
            self.y_bottom1 = self.height - char_height - 10

        except Exception as e:
            logger.error(f"Error loading image paths: {e}")
            raise

    def load_theme(self):
        """Load theme resources, falling back to defaults for anything not provided."""
        theme_name = self.config.get("theme", "bjorn")
        theme_dir = os.path.join(self.currentdir, "themes", theme_name)

        # Defaults (already set by load_fonts/load_images/initialize_paths)
        self.display_name = "BJORN"
        self.menu_title = "Pager Bjorn"
        self.web_title = "Bjorn Cyberviking"
        self.theme_bg_color = [255, 255, 255]
        self.theme_text_color = [0, 0, 0]
        self.theme_accent_color = [128, 128, 128]
        self.theme_preferred_orientation = None
        self.theme_layout_portrait = {}
        self.theme_layout_landscape = {}
        self.theme_title_font_color = None
        self.theme_title_font_size = None
        self.theme_title_y_offset = 0

        # Load theme.json if the theme directory exists
        theme_json_path = os.path.join(theme_dir, "theme.json")
        if os.path.isfile(theme_json_path):
            try:
                with open(theme_json_path, 'r') as f:
                    theme_data = json.load(f)
                self.display_name = theme_data.get("display_name", self.display_name)
                self.menu_title = theme_data.get("menu_title", self.menu_title)
                self.web_title = theme_data.get("web_title", self.web_title)
                self.theme_bg_color = theme_data.get("bg_color", self.theme_bg_color)
                self.theme_text_color = theme_data.get("text_color", self.theme_text_color)
                self.theme_accent_color = theme_data.get("accent_color", self.theme_accent_color)
                self.theme_preferred_orientation = theme_data.get("preferred_orientation", None)
                self.theme_layout_portrait = theme_data.get("layout_portrait", {})
                self.theme_layout_landscape = theme_data.get("layout_landscape", {})
                self.animation_mode = theme_data.get("animation_mode", "random")
                self.theme_image_display_delaymin = theme_data.get("image_display_delaymin", None)
                self.theme_image_display_delaymax = theme_data.get("image_display_delaymax", None)
                self.theme_comment_delaymin = theme_data.get("comment_delaymin", None)
                self.theme_comment_delaymax = theme_data.get("comment_delaymax", None)
                self.theme_title_font_color = theme_data.get("title_font_color", None)
                self.theme_title_font_size = theme_data.get("title_font_size", None)
                self.theme_title_y_offset = theme_data.get("title_y_offset", 0)
                logger.info(f"Loaded theme '{theme_name}': display_name='{self.display_name}'")
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Error reading theme.json for '{theme_name}': {e}")
        else:
            logger.info(f"Theme '{theme_name}' not found at {theme_dir}, using defaults")

        # Override title font if theme provides one
        theme_font = os.path.join(theme_dir, "fonts", "title.TTF")
        if os.path.isfile(theme_font):
            self.font_viking_path = theme_font
            logger.info(f"Theme font: {theme_font}")

        # Override static images (icons, frise, etc.) if theme provides them
        theme_images_dir = os.path.join(theme_dir, "images")
        if os.path.isdir(theme_images_dir):
            for name in list(self.static_images.keys()):
                theme_img = self._find_image(theme_images_dir, name)
                if theme_img:
                    self.static_images[name] = theme_img
            logger.info(f"Theme static images: {theme_images_dir}")

        # Override comments file if theme provides one
        theme_comments = os.path.join(theme_dir, "comments", "comments.json")
        if os.path.isfile(theme_comments):
            self.commentsfile = theme_comments
            logger.info(f"Theme comments: {theme_comments}")

        # Override character images (status images + animation frames) if theme provides them
        theme_status_dir = os.path.join(theme_dir, "images", "status")
        if os.path.isdir(theme_status_dir):
            logger.info(f"Theme status images: {theme_status_dir}")
            # Override main status images (one per action)
            for b_class, default_path in list(self.status_images.items()):
                theme_path = self._find_image(os.path.join(theme_status_dir, b_class), b_class)
                if theme_path:
                    self.status_images[b_class] = theme_path

            # Override animation frame series
            for status in list(self.image_series.keys()):
                theme_action_dir = os.path.join(theme_status_dir, status)
                if os.path.isdir(theme_action_dir):
                    theme_frames = []
                    for image_name in sorted(os.listdir(theme_action_dir)):
                        if self._is_image(image_name) and re.search(r'\d', image_name):
                            theme_frames.append(os.path.join(theme_action_dir, image_name))
                    if theme_frames:
                        self.image_series[status] = theme_frames
                        logger.debug(f"Theme override: {len(theme_frames)} frames for {status}")


    def update_bjornstatus(self):
        """Update current status image path."""
        try:
            if self.bjornorch_status in self.status_images:
                self.bjornstatusimage_path = self.status_images[self.bjornorch_status]
            else:
                logger.warning(f"No image for status {self.bjornorch_status}, using IDLE")
                self.bjornstatusimage_path = self.status_images.get('IDLE')

            self.bjornstatustext = self.bjornorch_status
        except Exception as e:
            logger.error(f"Error updating bjorn status: {e}")

    def update_image_randomizer(self):
        """Select the next animation frame for current status."""
        try:
            status = self.bjornstatustext
            frames = self.image_series.get(status)
            if not frames:
                frames = self.image_series.get("IDLE")
                if not frames:
                    self.current_image_path = None
                    return
                status = "IDLE"

            if getattr(self, 'animation_mode', 'random') == 'sequential':
                # Reset frame index when status changes
                if getattr(self, '_last_seq_status', None) != status:
                    self._frame_index = 0
                    self._last_seq_status = status
                self.current_image_path = frames[self._frame_index % len(frames)]
                self._frame_index += 1
            else:
                self.current_image_path = frames[random.randint(0, len(frames) - 1)]
        except Exception as e:
            logger.error(f"Error updating image randomizer: {e}")

    def get_effective_delays(self):
        """Return (min, max) image display delays, preferring theme values unless overridden."""
        if not getattr(self, 'override_theme_delays', False):
            dmin = getattr(self, 'theme_image_display_delaymin', None)
            dmax = getattr(self, 'theme_image_display_delaymax', None)
            if dmin is not None and dmax is not None:
                return dmin, dmax
        return self.image_display_delaymin, self.image_display_delaymax

    def get_effective_comment_delays(self):
        """Return (min, max) comment delays, preferring theme values unless overridden."""
        if not getattr(self, 'override_theme_comment_delays', False):
            dmin = getattr(self, 'theme_comment_delaymin', None)
            dmax = getattr(self, 'theme_comment_delaymax', None)
            if dmin is not None and dmax is not None:
                return dmin, dmax
        return self.comment_delaymin, self.comment_delaymax

    def wrap_text(self, text, max_chars=40):
        """Wrap text to fit within a specified character width."""
        try:
            lines = []
            words = text.split()
            line = ''
            for word in words:
                if len(line) + len(word) + 1 <= max_chars:
                    line = line + (' ' if line else '') + word
                else:
                    if line:
                        lines.append(line)
                    line = word
            if line:
                lines.append(line)
            return lines
        except Exception as e:
            logger.error(f"Error wrapping text: {e}")
            return [text]

    def read_data(self):
        """Read data from the CSV file."""
        self.initialize_csv()
        data = []
        with open(self.netkbfile, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                data.append(row)
        return data

    def write_data(self, data):
        """Write data to the CSV file."""
        with open(self.actions_file, 'r') as file:
            actions = json.load(file)
        action_names = [action["b_class"] for action in actions if "b_class" in action]

        if os.path.exists(self.netkbfile):
            with open(self.netkbfile, 'r') as file:
                reader = csv.DictReader(file)
                existing_headers = reader.fieldnames
                existing_data = list(reader)
        else:
            existing_headers = []
            existing_data = []

        new_headers = ["MAC Address", "IPs", "Hostnames", "Alive", "Ports"] + action_names
        missing_headers = [header for header in new_headers if header not in existing_headers]
        headers = existing_headers + missing_headers

        mac_to_existing_row = {row["MAC Address"]: row for row in existing_data}

        for new_row in data:
            mac_address = new_row["MAC Address"]
            if mac_address in mac_to_existing_row:
                existing_row = mac_to_existing_row[mac_address]
                for key, value in new_row.items():
                    if value:
                        existing_row[key] = value
            else:
                mac_to_existing_row[mac_address] = new_row

        with open(self.netkbfile, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=headers)
            writer.writeheader()
            for row in mac_to_existing_row.values():
                writer.writerow(row)

    def update_stats(self):
        """Update the stats based on formulas."""
        self.coinnbr = int((self.networkkbnbr * 5 + self.crednbr * 5 + self.datanbr * 5 +
                          self.zombiesnbr * 10 + self.attacksnbr * 5 + self.vulnnbr * 2))
        self.levelnbr = int((self.networkkbnbr * 0.1 + self.crednbr * 0.2 + self.datanbr * 0.1 +
                           self.zombiesnbr * 0.5 + self.attacksnbr + self.vulnnbr * 0.01))

