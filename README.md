<p align="center">
  <img src="bjorn-themes.png" width="500" alt="Bjorn - Payload for the Hak5 WiFi Pineapple Pager - Now With Theme Support">
</p>

A port/rewrite of [Bjorn](https://github.com/infinition/Bjorn) - the autonomous network reconnaissance Tamagotchi - for the WiFi Pineapple Pager.

<p align="center">
  <img src="screenshots/01-pager-display-bjorn-ssh.png" width="160" alt="Bjorn SSH Attack">
  <img src="screenshots/02-pager-display-vuln-scan.png" width="160" alt="Bjorn Vuln Scan">
  <img src="screenshots/03-pager-display-bjorn-sql.png" width="160" alt="Bjorn SQL Attack">
  <img src="screenshots/04-pager-display-bjorn-smb.png" width="160" alt="Bjorn SMB Attack">
</p>

## What is Bjorn?

Bjorn is a Tamagotchi-style autonomous network reconnaissance companion. It automatically:

- **Scans networks** for live hosts and open ports
- **Scans for vulnerabilities** using nmap NSE scripts with batched HTTP scanning
- **Brute forces** discovered services (FTP, SSH, Telnet, SMB, RDP, MySQL)
- **Exfiltrates data** when credentials are found
- **Displays status** with cute Viking animations

## Features

- **Autonomous Operation** - Set it and forget it. Bjorn continuously scans and attacks.
- **Host-by-Host Attack Strategy** - Runs all applicable attacks on one host before moving to the next
- **Network Discovery** - ARP scanning with ICMP ping fallback for alive host detection
- **Hostname Resolution** - Multiple fallback methods (reverse DNS, NetBIOS, mDNS, nmap)
- **Port Scanning** - Configurable port list with nmap integration
- **Vulnerability Scanning** - Nmap NSE script-based vuln scanning with batched HTTP checks optimized for MIPS
- **Manual Target Entry** - Add any IP or hostname as a target, including external hosts not on the local network
- **Virtual Host Support** - Scan multiple hostnames on the same IP with proper HTTP `Host:` header handling
- **Credential Brute Force** - Dictionary attacks against discovered services
- **Guest/Anonymous Detection** - Detects and logs guest access, skips brute force to avoid false positives
- **File Exfiltration** - Automatically steals sensitive files from compromised hosts
- **SQL Data Theft** - Dumps database tables from MySQL servers
- **Web Interface** - Real-time log viewer and control panel at `http://<pager-ip>:8000`
- **LCD Display** - Status updates on the Pager's full color screen with auto-dim for battery saving
- **Battery Indicator** - Real-time battery percentage in the header with charging state, auto-hides when unavailable

## Supported Protocols

| Protocol | Port | Brute Force | File Stealing | Status |
|----------|------|-------------|---------------|--------|
| FTP      | 21   | Yes         | Yes           | Ported |
| SSH      | 22   | Yes         | Yes           | Ported |
| Telnet   | 23   | Yes         | Yes           | Ported |
| SMB      | 445  | Yes         | Yes           | Ported |
| MySQL    | 3306 | Yes         | Yes           | Ported |
| RDP      | 3389 | Yes         | Disabled*     | Ported |

*RDP file exfiltration requires full xfreerdp with drive channels (not available on MIPS)

## Requirements

- WiFi Pineapple Pager (tested on firmware 1.0.7)
- **Network connection** - Pager must be connected to a network to scan (WiFi client mode or Ethernet/USB)
- **Internet connection** (first run only) - Required to install Python3 and nmap via opkg
- All Python dependencies are bundled in `lib/` - only system packages need internet

## Installation

1. Copy the `payloads/` directory to your Pager's SD card:
   ```bash
   scp -r payloads/ root@<pager-ip>:/root/
   ```

2. Launch from the Pager's payload menu: **Reconnaissance > Bjorn**

3. Press **GREEN** to start Bjorn

## Usage

### Graphical Menu

<p align="center">
  <img src="screenshots/00-pager-main-menu.png" width="400" alt="Main Menu">
</p>

When launching Bjorn, a graphical menu is displayed on the Pager LCD:

1. Dependencies are checked automatically
2. Network connectivity is verified
3. The menu displays:
   - **Start Raid** — Begin scanning and attacking
   - **Interface** — Select which network interface to use (LEFT/RIGHT to cycle)
   - **Web UI** — Toggle the web interface on/off (LEFT/RIGHT to toggle)
   - **Clear Data** — Submenu to clear logs, credentials, stolen data, or all data
   - **Exit** — Return to the Pager launcher

Use **UP/DOWN** to navigate, **A (GREEN)** to select, **B (RED)** to go back.

### Controls While Running

| Button | Action |
|--------|--------|
| **B (RED)** | Open Pause Menu |

### Pause Menu

<p align="center">
  <img src="screenshots/00b-pager-pause-menu.png" width="400" alt="Pause Menu">
</p>

Press **B** while Bjorn is running to open the pause menu:

| Option | Description |
|--------|-------------|
| **BACK** | Return to Bjorn |
| **Main Menu** | Stop Bjorn and return to the graphical start menu |
| **> Pagergotchi** | Hand off to Pagergotchi (only shown if installed) |
| **Exit Bjorn** | Stop Bjorn and return to the Pager launcher |

The pause menu also includes an integrated **brightness control** — use **UP/DOWN** to adjust brightness (20-100%), **LEFT/RIGHT** to navigate menu options, **GREEN** to confirm, **RED** to go back.

**Payload handoff:** Bjorn dynamically discovers other payloads via `launch_*.sh` scripts in the payload directory. Each launcher script declares a `# Title:` and `# Requires:` path — if the required path exists, the launcher appears as a menu option. Selecting it writes the launcher path to `data/.next_payload` and exits with code 42, which `payload.sh` picks up to launch the target payload.

The screen automatically dims after a configurable timeout to save battery. Any button press wakes the screen.

### Web Interface

Access the web UI at `http://<pager-ip>:8000`. It is a single-page app with the following tabs:

<img src="screenshots/05-web-dashboard.png" width="800" alt="Dashboard">

| Tab | Description |
|-----|-------------|
| **Dashboard** | Orchestrator status, live stats grid (targets, credentials, attacks, vulns, ports, data stolen, zombies, level, gold, netKB), and integrated log console with level filters (ALL/INFO/WARN/ERROR), auto-scroll, and incremental log fetching |
| **Network** | Host cards with color-coded status (green=alive, red=dead, gold=pwned) and per-protocol attack badges showing brute force and file steal results for each host |
| **Attacks** | Attack timeline with chronological history. Manual mode with target/port/action dropdowns, custom target input (any IP or hostname), execute and stop buttons, running status indicator, and live attack log output. Vulnerability scanning available per-port or across all open ports |
| **Loot** | Three sub-tabs: Credentials (grouped by protocol), Stolen Files (collapsible tree with download links), and Attack Logs (categorized per-module log files with download links) |
| **Config** | All settings from `shared_config.json` rendered as a form with collapsible sections, toggle switches, and save/restore buttons |
| **Terminal** | Execute commands directly on the device with command history (up/down arrows, persisted in session) |
| **Bjorn** | Live LCD mirror — renders the Pager's raw RGB565 framebuffer in the browser. Scroll-to-zoom on desktop, pinch-to-zoom on mobile |

Only the active tab polls the server — inactive tabs stop polling to conserve device resources.

<details>
<summary>Network Tab</summary>

<img src="screenshots/06-web-network.png" width="800" alt="Network">
</details>

<details>
<summary>Attacks Tab — Manual Mode</summary>

<img src="screenshots/07-web-manual-attack-mode.png" width="800" alt="Manual Attack Mode">
<img src="screenshots/08-web-manual-any-host.png" width="800" alt="Add Any Host">
</details>

<details>
<summary>Loot Tab — Credentials, Files, Vulnerabilities, Logs</summary>

<img src="screenshots/09-web-loot-credentials.png" width="800" alt="Credentials">
<img src="screenshots/10-web-loot-steal-files.png" width="800" alt="Stolen Files">
<img src="screenshots/11-web-loot-vulnerabilities.png" width="800" alt="Vulnerabilities">
<img src="screenshots/12-web-loot-attack-logs.png" width="800" alt="Attack Logs">
</details>

<details>
<summary>Config Tab</summary>

<img src="screenshots/13-web-config.png" width="800" alt="Config">
<img src="screenshots/14-web-config-more.png" width="800" alt="Config More">
</details>

<details>
<summary>Terminal Tab</summary>

<img src="screenshots/15-web-terminal.png" width="800" alt="Terminal">
</details>

## Configuration

Edit `config/shared_config.json` to customize Bjorn's behavior:

### General Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `manual_mode` | false | Enable manual attack mode (disables orchestrator) |
| `websrv` | true | Enable the web server |
| `debug_mode` | true | Enable debug mode |
| `retry_success_actions` | false | Retry actions that previously succeeded |
| `retry_failed_actions` | true | Retry actions that previously failed |
| `blacklist_gateway` | true | Automatically blacklist the network gateway |
| `blacklistcheck` | true | Enable blacklist checking |

### Timing Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `scan_interval` | 180 | Seconds between network scans |
| `failed_retry_delay` | 600 | Seconds before retrying failed actions |
| `success_retry_delay` | 900 | Seconds before retrying successful actions |
| `startup_delay` | 10 | Delay before starting orchestrator |
| `web_delay` | 2 | Web server startup delay |
| `screen_delay` | 1 | Screen update interval |
| `livestatus_delay` | 8 | Seconds between livestatus CSV updates |

### Network Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `scan_network_prefix` | 24 | Network prefix for scanning (e.g., /24) |
| `nmap_scan_aggressivity` | -T2 | Nmap timing template (-T0 to -T5) |
| `portlist` | [...] | List of ports to scan (41 ports by default) |
| `mac_scan_blacklist` | [] | MAC addresses to exclude from scanning |
| `ip_scan_blacklist` | [] | IP addresses to exclude from scanning |

### File Stealing Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `steal_max_depth` | 3 | Maximum directory depth to search |
| `steal_max_files` | 500 | Maximum files to discover per host |
| `steal_file_names` | [...] | Specific filenames to steal (e.g., `id_rsa`, `.env`) |
| `steal_file_extensions` | [...] | File extensions to steal (e.g., `.pem`, `.sql`, `.db`) |

### Performance Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `worker_threads` | 5 | Number of concurrent brute force threads |
| `bruteforce_queue_timeout` | 600 | Seconds before a queued brute force task times out |

### Time Wait Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `timewait_ftp` | 0 | Delay between FTP brute force attempts (seconds) |
| `timewait_ssh` | 0 | Delay between SSH brute force attempts (seconds) |
| `timewait_telnet` | 0 | Delay between Telnet brute force attempts (seconds) |
| `timewait_smb` | 0 | Delay between SMB brute force attempts (seconds) |
| `timewait_sql` | 0 | Delay between MySQL brute force attempts (seconds) |
| `timewait_rdp` | 0 | Delay between RDP brute force attempts (seconds) |

### Display Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `screen_brightness` | 80 | Default screen brightness (20-100%) |
| `screen_dim_brightness` | 25 | Brightness when dimmed (20-100%) |
| `screen_dim_timeout` | 60 | Seconds of inactivity before dimming |

### Theme Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `theme` | bjorn | Active theme folder name (see [Themes](#themes) below) |
| `override_theme_delays` | false | When enabled, global config delay values are used instead of per-theme values |

### Logging Settings
| Setting | Default | Description |
|---------|---------|-------------|
| `log_debug` | true | Log DEBUG level messages |
| `log_info` | true | Log INFO level messages |
| `log_warning` | true | Log WARNING level messages |
| `log_error` | true | Log ERROR level messages |
| `log_critical` | true | Log CRITICAL level messages |

### Dictionary Files

Customize brute force wordlists in `resources/dictionary/`:
- `users.txt` - Usernames to try
- `passwords.txt` - Passwords to try

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

## Attack Flow

Bjorn processes hosts one at a time, running all applicable attacks before moving to the next:

1. **Network Scan** - Discover alive hosts and open ports
2. **For each host:**
   - Run vulnerability scan (nmap NSE scripts) on open ports
   - Run all brute force attacks (SSH, FTP, SMB, Telnet, SQL, RDP)
   - Run all file stealing actions for successful brute forces
   - Move to the next host
3. **Repeat** - Continuous scanning for new hosts

### Action Status Messages

| Status | Meaning |
|--------|---------|
| `success` | Credentials found or files stolen |
| `no_creds_found` | Brute force completed, no valid credentials |
| `error` | Exception or connection error occurred |

Guest/anonymous access is automatically detected and saved to credentials files.

## Output Locations

All data is stored in `/mmc/root/loot/bjorn/`:

```
/mmc/root/loot/bjorn/
├── netkb.csv              # Network knowledge base (discovered hosts)
├── livestatus.csv         # Current scan status
├── logs/                  # Application logs
├── archives/              # Archived netkb.csv files
└── output/
    ├── crackedpwd/        # Cracked credentials by protocol
    │   ├── ftp.csv
    │   ├── ssh.csv
    │   ├── smb.csv
    │   ├── sql.csv
    │   ├── telnet.csv
    │   └── rdp.csv
    ├── data_stolen/       # Exfiltrated files by protocol/host
    │   ├── ftp/<mac>_<ip>/
    │   ├── ssh/<mac>_<ip>/
    │   ├── smb/<mac>_<ip>/
    │   ├── sql/<mac>_<ip>/     # Database table dumps
    │   ├── telnet/<mac>_<ip>/
    │   └── recon/file_listings/  # Complete file listings
    ├── scan_results/      # Network scan results
    └── vulnerabilities/   # Nmap vulnerability scan results
```

## Themes

Bjorn supports a theme system that lets you customize the display name, fonts, colors, animations, and commentary personality. All themes support both portrait and landscape display orientations. Themes live in `themes/` and are selected via the `theme` setting in `shared_config.json` or the web UI Config tab.

### Included Themes

| Theme | Description |
|-------|-------------|
| `bjorn` | Default Viking theme with Norse personality and Celtic knot divider |
| `clown` | CLOWNSEC theme with jester personality, circus commentary, and random HONKs |
| `pirate` | Cap'n Plndr pirate theme with seafaring personality and nautical commentary |
| `knight` | Sir Haxalot medieval knight theme with chivalric personality |

#### ClownSec

| | | | |
|---|---|---|---|
| ![ClownSec 1](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/clownsec-1.png) | ![ClownSec 2](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/clownsec-2.png) | ![ClownSec 3](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/clownsec-3.png) | ![ClownSec 4](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/clownsec-4.png) |

#### Sir Haxalot (Knight)

| | | | |
|---|---|---|---|
| ![Knight 1](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/knight-1.png) | ![Knight 2](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/knight-2.png) | ![Knight 3](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/knight-3.png) | ![Knight 4](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/knight-4.png) |

#### Cap'n Plndr (Pirate)

| | | | |
|---|---|---|---|
| ![Pirate 1](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/pirate-1.png) | ![Pirate 2](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/pirate-2.png) | ![Pirate 3](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/pirate-3.png) | ![Pirate 4](payloads/user/reconnaissance/pager_bjorn/themes/screenshots/pirate-4.png) |

### Switching Themes

Change the theme from the **startup menu** using LEFT/RIGHT on the Theme option, from the **Config** tab in the web UI, or by editing `config/shared_config.json` directly:

```json
"theme": "clown"
```

### Creating a Custom Theme

Create a new folder under `themes/` with the following structure:

```
themes/
  my_theme/
    theme.json               # Required - theme metadata and colors
    fonts/
      title.TTF              # Custom title font
    images/
      frise.bmp              # Divider bar image
      battery.png            # Battery indicator icon (displayed in header)
      target.bmp             # Stats icons (target, port, vuln, cred, etc.)
      ...
      status/                # Character animations per action
        IDLE/
          IDLE.png            # Supports PNG (with alpha) and BMP
          IDLE1.png
          ...
        NetworkScanner/
          NetworkScanner.png
          ...
        SSHBruteforce/
          ...
    comments/
      comments.json          # Commentary lines by action type
```

### theme.json Format

```json
{
    "display_name": "MYTHEME",
    "menu_title": "My Theme",
    "web_title": "My Theme - Cyber Tool",
    "bg_color": [255, 255, 255],
    "text_color": [0, 0, 0],
    "accent_color": [128, 128, 128],
    "animation_mode": "random",
    "image_display_delaymin": 2,
    "image_display_delaymax": 8,
    "comment_delaymin": 15,
    "comment_delaymax": 30
}
```

| Field | Description |
|-------|-------------|
| `display_name` | Shown in the LCD header (e.g., "BJORN", "CLOWNSEC") |
| `menu_title` | Shown on the startup menu screen |
| `web_title` | Browser tab title for the web UI |
| `bg_color` | Background color `[R, G, B]` for the LCD display |
| `text_color` | Text color `[R, G, B]` for the LCD display |
| `accent_color` | Accent color `[R, G, B]` for dividers and highlights |
| `animation_mode` | How status animation frames are played: `"random"` (default) picks a random frame each cycle, `"sequential"` plays frames in order for smooth animation |
| `image_display_delaymin` | Minimum seconds between animation frame changes (overrides global config) |
| `image_display_delaymax` | Maximum seconds between animation frame changes (overrides global config) |
| `comment_delaymin` | Minimum seconds between LCD comment updates (overrides global config) |
| `comment_delaymax` | Maximum seconds between LCD comment updates (overrides global config) |
| `title_y_offset` | Pixel offset to nudge the header title up (negative) or down (positive) for vertical centering with custom fonts |

The four delay fields are optional. When provided, they override the global config values for that theme. To force the global config values to take effect regardless of theme settings, enable the **Override Theme Animation Delays** toggle (`override_theme_delays`) in the web UI Config tab.

### Image Format

- **BMP** images are loaded directly
- **PNG** images with alpha transparency are automatically composited against the theme's `bg_color` and cached as BMP on first load (a loading screen is shown during initial processing)
- Status animation frames are numbered sequentially (e.g., `IDLE.png`, `IDLE1.png`, `IDLE2.png`, ...)
- Any resources not provided by the theme fall back to the defaults in `resources/`

### Comments Format

The `comments.json` file contains commentary lines grouped by action type. Each action key maps to a list of strings that are randomly displayed during that action:

```json
{
    "IDLE": ["Waiting for targets...", "Nothing to do..."],
    "NetworkScanner": ["Scanning the network...", "Looking for hosts..."],
    "SSHBruteforce": ["Trying SSH credentials...", "Knocking on port 22..."],
    ...
}
```

Supported action keys: `IDLE`, `NetworkScanner`, `NmapVulnScanner`, `SSHBruteforce`, `FTPBruteforce`, `TelnetBruteforce`, `SMBBruteforce`, `SQLBruteforce`, `RDPBruteforce`, `StealFilesSSH`, `StealFilesFTP`, `StealFilesSMB`, `StealFilesTelnet`, `StealDataSQL`, `LogStandalone`, `LogStandalone2`, `ZombifySSH`.

---

## Architecture

```
pager_bjorn/
├── payload.sh             # Launcher script (handles exit codes, spinner)
├── bjorn_menu.py          # Graphical startup menu (interface select, clear data)
├── Bjorn.py               # Main entry point
├── display.py             # Pager LCD display (pagerctl, pause menu, payload handoff)
├── orchestrator.py        # Task scheduler
├── shared.py              # Shared state & config
├── utils.py               # Web server utilities
├── webapp.py              # HTTP server (web UI + API)
├── logger.py              # Logging with per-module log files
├── pagerctl.py            # Pager hardware interface
├── libpagerctl.so         # Native display library
├── comment.py             # Viking commentary engine
├── init_shared.py         # Shared data initializer
├── timeout_utils.py       # Timeout helpers
├── launch_pagergotchi.sh  # Handoff launcher for Pagergotchi
├── bin/                   # Native binaries (MIPS)
│   ├── nmap               # Network scanner
│   ├── sfreerdp           # FreeRDP client (auth-only)
│   ├── xfreerdp           # FreeRDP client (full)
│   ├── smb2-cat           # libsmb2 file reader
│   ├── smb2-find          # libsmb2 file finder
│   └── smb2-share-enum    # libsmb2 share enumerator
├── lib/                   # Bundled Python packages + native libs
│   ├── paramiko/          # SSH library
│   ├── cryptography/      # Crypto (paramiko dep)
│   ├── bcrypt/            # Password hashing (paramiko dep)
│   ├── nacl/              # PyNaCl (paramiko dep)
│   ├── getmac/            # MAC address lookup
│   ├── pymysql/           # MySQL client
│   ├── nmap/              # python-nmap
│   ├── smb/               # pysmb
│   ├── tqdm/              # Progress bars
│   ├── libssh2.so.1       # SSH2 native lib
│   ├── liblua5.4.so.0     # Lua (nmap dep)
│   ├── libsodium.so       # Crypto native lib
│   └── ...
├── share/                 # Data files
│   └── nmap/              # Nmap scripts, service probes, NSE libs
├── actions/               # Attack modules
│   ├── scanning.py            # Network + port scanner
│   ├── nmap_vuln_scanner.py   # Vulnerability scanner (batched NSE)
│   ├── ftp_connector.py       # FTP brute force
│   ├── ssh_connector.py       # SSH brute force
│   ├── telnet_connector.py    # Telnet brute force
│   ├── smb_connector.py       # SMB brute force
│   ├── sql_connector.py       # MySQL brute force
│   ├── rdp_connector.py       # RDP brute force
│   ├── steal_files_ftp.py     # FTP file exfiltration
│   ├── steal_files_ssh.py     # SSH file exfiltration
│   ├── steal_files_telnet.py  # Telnet file exfiltration
│   ├── steal_files_smb.py     # SMB file exfiltration
│   ├── steal_data_sql.py      # MySQL data exfiltration
│   └── IDLE.py                # Idle/cooldown action
├── config/
│   ├── shared_config.json
│   └── actions.json
├── themes/                # Theme packs
│   ├── bjorn/             # Default Viking theme
│   ├── clown/             # CLOWNSEC jester theme
│   ├── pirate/            # Cap'n Plndr pirate theme
│   └── knight/            # Sir Haxalot knight theme
├── web/                   # Web UI (single-page app)
│   ├── index.html         # SPA shell
│   ├── css/
│   │   └── bjorn.css      # Viking theme
│   ├── scripts/
│   │   ├── app.js         # SPA router & polling manager
│   │   ├── dashboard.js   # Stats grid + status
│   │   ├── console.js     # Integrated log console
│   │   ├── network.js     # Host cards + attack badges
│   │   ├── attacks.js     # Timeline + manual mode
│   │   ├── loot.js        # Credentials, files, vulns, logs
│   │   ├── config.js      # Settings editor
│   │   ├── terminal.js    # Device command execution
│   │   └── bjorn.js       # LCD framebuffer mirror
│   └── fonts/
│       └── Viking.TTF
└── resources/
    ├── dictionary/        # Wordlists
    ├── fonts/             # Display fonts
    └── images/            # Viking animations
```

## Clearing Data

Use the **Clear Data** submenu from the graphical startup menu:

| Option | What it clears |
|--------|----------------|
| **Clear Logs** | All log files in `logs/` |
| **Clear Credentials** | Cracked password CSVs in `output/crackedpwd/` |
| **Clear Stolen Data** | Exfiltrated files in `output/data_stolen/` |
| **Clear All** | Everything above plus scan results, vulnerabilities, zombies, archives, netkb, and livestatus |

Each option requires confirmation before proceeding.

## Logging

Logs are stored in `/mmc/root/loot/bjorn/logs/` with one file per module. Default log level is INFO. To enable debug logging, edit the `level=logging.INFO` to `level=logging.DEBUG` in the respective Python files.

View combined logs via the web interface or:
```bash
tail -f /mmc/root/loot/bjorn/logs/*.log
```

---

## Test Targets

A Docker-based vulnerable test environment is provided in `test_targets/`. See [`test_targets/README.md`](test_targets/README.md) for setup and usage.

---

## Troubleshooting

### Bjorn won't start
- Check that the Pager has internet access (required for first run to install dependencies)
- The payload automatically installs Python3 and nmap - check the display for installation progress
- If installation fails, try running the payload again with internet connectivity

### No hosts discovered
- Check that you're connected to an active network
- Verify the target network has hosts
- Check `mac_scan_blacklist` and `ip_scan_blacklist` in config

### Brute force takes too long
- Reduce the dictionary size in `resources/dictionary/`
- Increase `nmap_scan_aggressivity` (e.g., `-T4`)
- Reduce `portlist` to only essential ports

### Web interface not loading
- Verify Bjorn is running (`ps | grep python`)
- Check firewall rules
- Try accessing via the Pager's br-lan IP

---

## Manual Attack Mode

Manual mode pauses the orchestrator and gives you full control over individual attacks from the web UI.

### Adding Custom Targets

The Attacks tab includes a text input for adding any IP address or hostname as a target:

- **IP address** (e.g., `10.0.0.50`) - Added directly to the target list
- **Hostname** (e.g., `example.com`) - Resolved to IPv4 and added with hostname metadata
- Manual entries get `MAC Address = manual` to distinguish them from network-scanned hosts

### Virtual Host (vhost) Scanning

Multiple hostnames on the same IP are supported. Each hostname gets its own entry in the target list:

1. Add `site1.com` - resolves to `93.184.216.34`, shown as `93.184.216.34 (site1.com)`
2. Add `site2.com` - same IP, new entry shown as `93.184.216.34 (site2.com)`
3. Port scan either one - ports are shared across all entries for the same IP
4. Vuln scan `site1.com` - nmap sends `Host: site1.com` header for HTTP scripts
5. Vuln scan `site2.com` - nmap sends `Host: site2.com` header for HTTP scripts

This ensures HTTP vulnerability scripts hit the correct virtual host instead of just the server's default site.

### Vulnerability Scanning

Select a target IP, choose a port (or "All Open Ports"), and select "Vuln Scan" from the action dropdown:

- **Single port** - Scans only that port for vulnerabilities
- **All Open Ports** - Scans every open port on the host

HTTP ports (80, 443, 8080, 8443) use batched NSE scripts optimized for MIPS to avoid CPU starvation. Non-HTTP ports use `--script vuln` in a single pass.

---

## Credits

- **Original Bjorn**: [infinition](https://github.com/infinition/Bjorn)
- **Pager Port**: brAinphreAk
- **pagerctl / WiFi Pineapple Pager**: Hak5

## License

MIT License - See [LICENSE](LICENSE)

## Disclaimer

This tool is for authorized security testing and educational purposes only. Only use on networks you own or have explicit permission to test. The authors are not responsible for misuse.
