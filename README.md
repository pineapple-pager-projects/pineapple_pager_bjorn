# Pager Bjorn

A port of [Bjorn](https://github.com/infinition/Bjorn) - the autonomous network reconnaissance Tamagotchi - for the WiFi Pineapple Pager.

## What is Bjorn?

Bjorn is a Tamagotchi-style autonomous network reconnaissance companion. It automatically:

- **Scans networks** for live hosts and open ports
- **Brute forces** discovered services (FTP, SSH, Telnet, SMB, RDP, MySQL)
- **Exfiltrates data** when credentials are found
- **Displays status** with cute Viking animations

## Features

| Feature | Status | Notes |
|---------|--------|-------|
| Network Scanner | Ported | Uses getmac, nmap |
| Nmap Vuln Scanner | Ported | Requires nmap |
| FTP Brute Force | Ported | Uses built-in ftplib |
| SSH Brute Force | Ported | Uses paramiko |
| Telnet Brute Force | Ported | Uses built-in telnetlib |
| SMB Brute Force | TODO | Needs `smbclient` |
| RDP Brute Force | TODO | Needs `xfreerdp` (not available on Pager) |
| MySQL Brute Force | Ported | Uses pymysql |
| File Exfiltration (FTP) | Ported | |
| File Exfiltration (SSH) | Ported | |
| File Exfiltration (SMB) | TODO | Needs `smbclient` |
| File Exfiltration (RDP) | TODO | Needs `xfreerdp` |
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
   scp -r payloads/ root@<pager-ip>:/mmc/root/
   ```

2. Launch from the Pager's payload menu: **Reconnaissance → Bjorn**

3. Dependencies (nmap, paramiko, etc.) are **automatically installed** on first run

4. Press **GREEN** to start Bjorn

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
