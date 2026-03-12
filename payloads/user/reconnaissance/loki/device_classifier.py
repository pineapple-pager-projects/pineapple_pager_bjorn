# device_classifier.py
# MAC OUI vendor lookup and port-based device classification.

import os
import logging
from logger import Logger

logger = Logger(name="device_classifier.py", level=logging.INFO)

# Cached OUI database: prefix (6 hex chars uppercase) -> vendor name
_oui_db = None


def load_oui_database(path):
    """Parse nmap-mac-prefixes into a dict: 6-char hex prefix -> vendor name."""
    global _oui_db
    if _oui_db is not None:
        return _oui_db
    _oui_db = {}
    try:
        with open(path, 'r', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Format: "AABBCC Vendor Name"
                parts = line.split(None, 1)
                if len(parts) == 2 and len(parts[0]) == 6:
                    _oui_db[parts[0].upper()] = parts[1]
        logger.debug(f"Loaded {len(_oui_db)} OUI entries")
    except FileNotFoundError:
        logger.warning(f"OUI database not found: {path}")
    except Exception as e:
        logger.error(f"Error loading OUI database: {e}")
    return _oui_db


def lookup_vendor(mac, oui_db=None):
    """Return vendor name for a MAC address, or 'Unknown'."""
    if not mac:
        return "Unknown"
    if oui_db is None:
        oui_db = _oui_db or {}
    prefix = mac.replace(':', '').replace('-', '').replace('.', '')[:6].upper()
    return oui_db.get(prefix, "Unknown")


# --- Vendor keyword -> device type mapping ---
# Checked in order; first match wins.
_VENDOR_RULES = [
    # Printers
    (["Brother", "Canon", "Epson", "Lexmark", "Xerox", "Ricoh", "Konica", "Kyocera",
      "Sharp", "Zebra", "Dymo", "Star Micronics"], "Printer"),
    # HP has printers AND servers/workstations - handled specially below
    # Cameras
    (["Hikvision", "Dahua", "Axis Communications", "Reolink", "Amcrest", "Foscam",
      "Hanwha", "Vivotek", "Bosch Security", "FLIR"], "Camera/IP Cam"),
    # NAS
    (["Synology", "QNAP", "Drobo", "Buffalo", "Asustor", "TerraMaster"], "NAS"),
    # Smart speakers
    (["Sonos", "Amazon Technologies", "Harman"], "Smart Speaker"),
    # Routers / Network equipment
    (["Cisco", "Ubiquiti", "MikroTik", "Netgear", "TP-Link", "TP-LINK", "D-Link",
      "Linksys", "Zyxel", "Juniper", "Aruba", "Ruckus", "Fortinet", "Palo Alto",
      "SonicWall", "Meraki", "Peplink", "DrayTek", "Huawei Technologies"],
     "Router"),
    # Access points (some overlap with router vendors)
    (["Aruba", "Ruckus", "EnGenius", "Cambium"], "Access Point"),
    # Switches
    (["Allied Telesis", "Brocade", "Extreme Networks"], "Switch"),
    # Firewalls
    (["Fortinet", "Palo Alto", "SonicWall", "WatchGuard", "Barracuda",
      "Check Point"], "Firewall"),
    # VoIP
    (["Polycom", "Yealink", "Grandstream", "Snom", "Mitel", "Avaya",
      "Cisco-Linksys"], "VoIP Phone"),
    # Phones / Mobile
    (["Apple", "Samsung", "OnePlus", "Xiaomi", "Huawei Device", "Oppo", "Vivo",
      "Motorola Mobility", "Google", "LG Electronics", "Sony Mobile", "HTC",
      "Nokia", "Realme", "Nothing"], "Phone/Mobile"),
    # Tablets (some overlap with phone vendors - port signature refines)
    # Gaming consoles
    (["Nintendo", "Microsoft", "Sony Interactive"], "Gaming Console"),
    # TV / Media
    (["Roku", "LG Display", "TCL", "Hisense", "Vizio", "Chromecast"], "TV/Media"),
    # IoT / Smart Home
    (["Espressif", "Tuya", "Shelly", "Wemo", "Ring", "Nest", "ecobee",
      "Philips Lighting", "Signify", "LIFX", "Govee", "Meross",
      "TP-Link Smart Home"], "IoT/Smart Home"),
    # EV Chargers
    (["Tesla", "ChargePoint", "Wallbox", "Juice Technology", "Easee"], "EV Charger"),
    # Servers / workstations
    (["Dell", "Hewlett Packard Enterprise", "Supermicro", "Lenovo", "IBM"],
     "Server"),
    # Workstation / PC (broad)
    (["Intel", "ASUSTek", "Gigabyte", "MSI", "Acer", "Micro-Star",
      "ASRock", "Realtek"], "Workstation/PC"),
]

# Port sets for classification
_PRINTER_PORTS = {9100, 631, 515}
_CAMERA_PORTS = {554, 8554, 37777, 34567}
_SERVER_PORTS = {3306, 5432, 1433, 27017, 6379, 9200, 5672, 15672}
_VOIP_PORTS = {5060, 5061}
_GAMING_PORTS = {3074, 3478, 3479, 3480}


def classify_device(vendor, ports, ip=None, gateway_ip=None, services=None, os_info=None):
    """Classify a device based on vendor name, open ports, service banners, and OS info.

    Args:
        vendor: Vendor string from OUI lookup.
        ports: Iterable of port numbers (ints or strings).
        ip: Device IP address (optional, for gateway detection).
        gateway_ip: Network gateway IP (optional).
        services: Services string from netkb (e.g. "22:ssh/OpenSSH 8.4;80:http/Apache") or None.
        os_info: OS detection string (e.g. "Linux 4.15") or None.

    Returns:
        Device type string from the extended category set.
    """
    port_set = set()
    for p in (ports or []):
        try:
            port_set.add(int(p))
        except (ValueError, TypeError):
            pass

    # --- Service banner classification (high confidence) ---
    services_upper = (services or "").upper()
    if services_upper:
        # Router indicators from service banners
        if any(kw in services_upper for kw in ["MIKROTIK", "ROUTEROS", "OPENWRT", "DD-WRT", "UBIQUITI"]):
            return "Router"
        # Printer indicators
        if any(kw in services_upper for kw in ["CUPS", "JETDIRECT", "PRINTER", "IPP"]):
            return "Printer"
        # Camera indicators
        if any(kw in services_upper for kw in ["HIKVISION", "DAHUA", "RTSP", "AXIS"]):
            return "Camera/IP Cam"
        # NAS indicators
        if any(kw in services_upper for kw in ["SYNOLOGY", "QNAP", "NETGEAR READYNAS"]):
            return "NAS"

    # --- OS-based classification hints (used as tiebreaker later) ---
    os_upper = (os_info or "").upper()
    os_hint = None
    if os_upper:
        if any(kw in os_upper for kw in ["ROUTEROS", "OPENWRT", "DD-WRT", "VYOS"]):
            return "Router"
        if "WINDOWS" in os_upper:
            os_hint = "Workstation/PC"
        elif "LINUX" in os_upper or "UNIX" in os_upper:
            os_hint = "Server"
        elif "IOS" in os_upper or "DARWIN" in os_upper:
            os_hint = "Phone/Mobile"

    # --- Gateway detection (highest priority) ---
    if ip and gateway_ip and ip == gateway_ip:
        return "Router"

    # --- Port-based overrides (high confidence) ---
    if port_set & _PRINTER_PORTS:
        return "Printer"

    if port_set & _CAMERA_PORTS:
        return "Camera/IP Cam"

    if port_set & _VOIP_PORTS:
        return "VoIP Phone"

    if port_set & _SERVER_PORTS:
        return "Server"

    # --- Vendor keyword matching ---
    vendor_upper = (vendor or "").upper()
    device_type = None

    # HP special case: check ports to disambiguate printer vs server vs workstation
    if any(kw in vendor_upper for kw in ["HEWLETT PACKARD", "HP INC", "HEWLETT-PACKARD"]):
        if port_set & _PRINTER_PORTS:
            return "Printer"
        if port_set & _SERVER_PORTS:
            return "Server"
        if 3389 in port_set:
            return "Workstation/PC"
        # Default HP with no distinguishing ports
        return "Workstation/PC"

    for keywords, dtype in _VENDOR_RULES:
        for kw in keywords:
            if kw.upper() in vendor_upper:
                device_type = dtype
                break
        if device_type:
            break

    # --- Port-based refinements ---
    if 3389 in port_set and len(port_set) > 2:
        # RDP with multiple ports strongly indicates Windows workstation
        if device_type not in ("Server", "Printer", "Camera/IP Cam"):
            return "Workstation/PC"

    if port_set and port_set <= {8080, 8443, 80, 443} and not device_type:
        return "IoT/Smart Home"

    return device_type or os_hint or "Unknown"
