# Pager Bjorn

A port of [Bjorn](https://github.com/infinition/Bjorn) - the autonomous network reconnaissance Tamagotchi - for the WiFi Pineapple Pager.

![Bjorn on Pager](screenshot.png)

## What is Bjorn?

Bjorn is a Tamagotchi-style autonomous network reconnaissance companion. It automatically:

- **Scans networks** for live hosts and open ports
- **Brute forces** discovered services (FTP, SSH, Telnet, SMB, RDP, MySQL)
- **Exfiltrates data** when credentials are found
- **Displays status** with cute Viking animations

## Display Icons

### Stats Grid (top-right)

| Position | Icon | Name | Description |
|----------|------|------|-------------|
| Row 1, Left | Target | `target` | Alive hosts found |
| Row 1, Middle | Folder | `port` | Open ports discovered |
| Row 1, Right | Stack | `vuln` | Vulnerabilities found |
| Row 2, Left | Lock | `cred` | Credentials cracked |
| Row 2, Middle | Skull | `zombie` | Compromised hosts |
| Row 2, Right | File | `data` | Data files stolen |

### Viking Stats (around character)

| Position | Icon | Name | Description |
|----------|------|------|-------------|
| Top-left | Coins | `coins` | Total score |
| Bottom-left | Up arrow | `level` | Bjorn's level |
| Top-right | Network | `networkkb` | Known hosts discovered |
| Bottom-right | Swords | `attacks` | Attacks performed |

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Network Scanner | Ported | getmac (bundled), nmap (system) |
| Nmap Vuln Scanner | Ported | nmap (system) |
| FTP Brute Force | Ported | ftplib (built-in) |
| SSH Brute Force | Ported | paramiko (bundled) |
| Telnet Brute Force | Ported | telnetlib (built-in) |
| SMB Brute Force | Ported | pysmb (bundled) |
| RDP Brute Force | Ported | sfreerdp (bundled, cross-compiled for MIPS) |
| MySQL Brute Force | Ported | pymysql (bundled) |
| File Exfiltration (FTP) | Ported | |
| File Exfiltration (SSH) | Ported | paramiko (bundled) |
| File Exfiltration (SMB) | Ported | pysmb (bundled) |
| File Exfiltration (RDP) | Disabled | Requires full xfreerdp with drive channels |
| Portrait Display | Ported | |
| Button Controls | Ported | |

## Requirements

- WiFi Pineapple Pager with firmware 1.x+
- Python3 and nmap (pre-installed on Pager)
- **Network connection** - Pager must be connected to a network to scan (WiFi client mode or Ethernet/USB)
- All Python dependencies are bundled - no internet required

## Installation

1. Copy the `payloads/` directory to your Pager's SD card:
   ```bash
   scp -r payloads/ root@<pager-ip>:/root/
   ```

2. Launch from the Pager's payload menu: **Reconnaissance → Bjorn**

3. Press **GREEN** to start Bjorn

All Python dependencies are bundled in `lib/` - no internet connection required.

## Usage

### Startup

When launching Bjorn:
1. Dependencies are checked automatically
2. Network connectivity is verified
3. If multiple networks are detected, select one:
   - **RED** = 1st network
   - **GREEN** = 2nd network
   - **UP** = 3rd network
4. Press **GREEN** to start, **RED** to exit

### Controls

| Button | Action |
|--------|--------|
| **GREEN** | Start Bjorn / Confirm |
| **RED** | Exit / Cancel |

### Exiting Bjorn

While Bjorn is running:
1. Press **RED** button
2. Confirmation dialog appears
3. Press **GREEN** to exit, **RED** to cancel

### Configuration

Edit `config/shared_config.json` to customize:

```json
{
    "scan_network_prefix": 24,     // Subnet size to scan (/24 = 254 hosts)
    "scan_interval": 180,          // Seconds between scans
    "startup_delay": 10,           // Delay before starting orchestrator
    "blacklistcheck": true         // Skip blacklisted MACs/IPs
}
```

### Dictionary Files

Customize brute force wordlists in `resources/dictionary/`:
- `users.txt` - Usernames to try
- `passwords.txt` - Passwords to try

### Data Storage

Bjorn stores discovered data in `/mmc/root/loot/bjorn/`:
- `netkb.csv` - Network knowledge base (all discovered hosts)
- `livestatus.csv` - Current scan statistics
- `output/crackedpwd/` - Successful credentials
- `logs/` - Debug logs

## Architecture

```
pager_bjorn/
├── Bjorn.py           # Main entry point
├── display.py         # Pager LCD display (pagerctl)
├── orchestrator.py    # Task scheduler
├── shared.py          # Shared state & config
├── pagerctl.py        # Pager hardware interface
├── libpagerctl.so     # Native display library
├── payload.sh         # Launcher script
├── bin/               # Native binaries (MIPS)
│   ├── sfreerdp       # FreeRDP client (auth-only)
│   ├── libssl.so.3    # OpenSSL (sfreerdp dep)
│   └── libcrypto.so.3 # OpenSSL (sfreerdp dep)
├── lib/               # Bundled Python packages
│   ├── paramiko/      # SSH library
│   ├── cryptography/  # Crypto (paramiko dep)
│   ├── getmac/        # MAC address lookup
│   ├── pymysql/       # MySQL client
│   ├── nmap/          # python-nmap
│   ├── smb/           # pysmb
│   └── ...
├── actions/           # Attack modules
│   ├── scanning.py    # Network scanner
│   ├── ftp_connector.py
│   ├── ssh_connector.py
│   ├── telnet_connector.py
│   ├── smb_connector.py
│   ├── rdp_connector.py
│   └── ...
├── config/
│   ├── shared_config.json
│   └── actions.json
└── resources/
    ├── dictionary/    # Wordlists
    ├── fonts/         # Display fonts
    └── images/        # Viking animations
```

## Credits

- **Original Bjorn**: [infinition](https://github.com/infinition/Bjorn)
- **Pager Port**: brAinphreAk
- **pagerctl**: Hak5

## License

MIT License - See [LICENSE](LICENSE)

## Disclaimer

This tool is for authorized security testing and educational purposes only. Only use on networks you own or have explicit permission to test. The authors are not responsible for misuse.
