# Loki Web Interface

Access the web UI at `http://<pager-ip>:8000`. It is a single-page app that provides real-time monitoring and control of Loki from any browser on the same network.

Only the active tab polls the server — inactive tabs stop polling to conserve device resources.

## Dashboard

<p align="center">
  <img src="screenshots/02-webui-dashboard.png" width="700" alt="Dashboard">
</p>

The Dashboard shows orchestrator status, a live stats grid (targets, credentials, attacks, vulns, ports, data stolen, zombies, level, gold, netKB), and an integrated log console with level filters (ALL/INFO/WARN/ERROR), auto-scroll, and incremental log fetching.

## Hosts

<p align="center">
  <img src="screenshots/03-webui-hostsview.png" width="700" alt="Hosts View">
</p>

Host cards with color-coded status (green=alive, red=dead, gold=pwned) and per-protocol attack badges showing brute force and file steal results for each host. Click a host to expand details including open ports, credentials, and vulnerabilities.

<details>
<summary>Host Export View</summary>
<p align="center">
  <img src="screenshots/04-webui-hosts-text-export.png" width="700" alt="Host Text Export">
</p>
</details>

## Attacks

<p align="center">
  <img src="screenshots/11-webui-attack.png" width="700" alt="Attacks Tab">
</p>

Attack timeline with chronological history. Manual mode with target/port/action dropdowns, custom target input (any IP or hostname), execute and stop buttons, running status indicator, and live attack log output. Vulnerability scanning available per-port or across all open ports.

<details>
<summary>Manual Attack Mode</summary>
<p align="center">
  <img src="screenshots/12-webui-manual-attack-mode.png" width="700" alt="Manual Attack Mode">
</p>

In manual mode, select a target, port, and action from the dropdowns. You can enter any IP address or hostname — including hosts on external networks. Each manual attack shows a live log of its progress.
</details>

## Loot

The Loot tab has four sub-tabs:

### Credentials

<p align="center">
  <img src="screenshots/08-webui-loot-credentials.png" width="700" alt="Credentials">
</p>

Cracked credentials grouped by protocol with username, password, host, and timestamp.

### Stolen Files

<p align="center">
  <img src="screenshots/05-webui-loot-stolen-files.png" width="700" alt="Stolen Files">
</p>

Collapsible file tree organized by protocol and host. Click any file to download it directly.

### Vulnerabilities

<p align="center">
  <img src="screenshots/06-webui-loot-cve-found.png" width="700" alt="Vulnerabilities">
</p>

Discovered vulnerabilities with CVE details, severity ratings, and affected hosts/ports.

### Attack Logs

<p align="center">
  <img src="screenshots/07-webui-loot-logfiles.png" width="700" alt="Attack Logs">
</p>

Categorized per-module log files with download links for offline analysis.

## Config

<p align="center">
  <img src="screenshots/09-webui-config.png" width="700" alt="Config">
</p>

All settings from `shared_config.json` rendered as a form with collapsible sections, toggle switches, and save/restore buttons. Changes take effect immediately — no restart required.

## Terminal

<p align="center">
  <img src="screenshots/09-webui-terminal.png" width="700" alt="Terminal">
</p>

Execute commands directly on the device. Supports command history with up/down arrows (persisted in session). Working directory is the Loki loot directory.

## Display

<p align="center">
  <img src="screenshots/10-webui-display.png" width="700" alt="Display Mirror">
</p>

Live LCD mirror — renders the Pager's raw RGB565 framebuffer in the browser in real time. Scroll-to-zoom on desktop, pinch-to-zoom on mobile. The tab label is themeable (configured in `theme.json` via the `web.nav_label_display` field).

## Tab Summary

| Tab | Description |
|-----|-------------|
| **Dashboard** | Orchestrator status, live stats grid, integrated log console |
| **Hosts** | Color-coded host cards with per-protocol attack badges |
| **Attacks** | Attack timeline, manual mode with custom targets and vuln scanning |
| **Loot** | Credentials, stolen files, vulnerabilities, and attack logs |
| **Config** | All settings as a live-editable form |
| **Terminal** | Device command execution with history |
| **Display** | Live LCD framebuffer mirror with zoom |
