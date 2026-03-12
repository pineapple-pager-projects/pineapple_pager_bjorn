# Loki Theme System

Loki supports a full theme system that customizes the display name, fonts, colors, LCD animations, menu backgrounds, pause menu styling, web UI appearance, and commentary personality. All themes support both portrait (222x480) and landscape (480x222) display orientations.

## Included Themes

| Theme | Display Name | Animation Mode | Author |
|-------|-------------|----------------|--------|
| `loki` | LOKI | Sequential | brAinphreAk |
| `bjorn` | BJORN | Random | infinition |
| `clown` | ClownSec | Random | brAinphreAk |
| `pirate` | Cap'n Plndr | Random | brAinphreAk |
| `knight` | Sir Haxalot | Sequential | Zombie Joe |

### Loki (Default)

<p align="center">
  <img src="screenshots/18-loki-theme-menu.png" width="480" alt="Loki Menu">
</p>
<p align="center">
  <img src="screenshots/26-loki-theme-landscape.png" width="320" alt="Loki Landscape">
  <img src="screenshots/31-loki-theme-portrait.png" width="148" alt="Loki Portrait">
</p>

### Bjorn

<p align="center">
  <img src="screenshots/20-bjorn-theme-menu.png" width="480" alt="Bjorn Menu">
</p>
<p align="center">
  <img src="screenshots/28-bjorn-theme-landscape.png" width="320" alt="Bjorn Landscape">
  <img src="screenshots/33-bjorn-theme-portrait.png" width="148" alt="Bjorn Portrait">
</p>

### ClownSec

<p align="center">
  <img src="screenshots/21-clown-theme-menu.png" width="480" alt="ClownSec Menu">
</p>
<p align="center">
  <img src="screenshots/29-clown-theme-landscape.png" width="320" alt="ClownSec Landscape">
  <img src="screenshots/34-clown-theme-portrait.png" width="148" alt="ClownSec Portrait">
</p>

### Cap'n Plndr (Pirate)

<p align="center">
  <img src="screenshots/19-pirate-theme-menu.png" width="480" alt="Pirate Menu">
</p>
<p align="center">
  <img src="screenshots/27-pirate-theme-landscape.png" width="320" alt="Pirate Landscape">
  <img src="screenshots/32-pirate-theme-portrait.png" width="148" alt="Pirate Portrait">
</p>

### Sir Haxalot (Knight)

<p align="center">
  <img src="screenshots/22-knight-theme-menu.png" width="480" alt="Knight Menu">
</p>
<p align="center">
  <img src="screenshots/30-knight-theme-landscape.png" width="320" alt="Knight Landscape">
  <img src="screenshots/35-knight-theme-portrait.png" width="148" alt="Knight Portrait">
</p>

## Switching Themes

Three ways to change themes:

1. **Startup menu** — Use LEFT/RIGHT on the Theme option (live preview on the LCD)
2. **Web UI** — Change the `theme` setting in the Config tab
3. **Config file** — Edit `config/shared_config.json`:
   ```json
   "theme": "pirate"
   ```

## Mood Presets

Each theme defines custom labels for the three mood presets available in the Settings menu. Moods are shortcuts that configure brute force, vuln scan, file steal, and attack order together.

| Theme | Target | Swarm | Recon |
|-------|--------|-------|-------|
| loki | Vendetta | Chaotic | Slither |
| bjorn | Raiding | Berserker | Scouting |
| clown | Psychotic | Silly | Mime Mode |
| pirate | Plundering | Broadside | Parley |
| knight | Crusading | Berserker | Chivalrous |

| Mood | Brute Force | Vuln Scan | File Steal | Attack Order |
|------|------------|-----------|------------|-------------|
| Target | ON | ON | ON | per_host |
| Swarm | ON | ON | ON | spread |
| Recon | OFF | OFF | OFF | spread |

---

# Creating a Custom Theme

## Directory Structure

Create a new folder under `themes/` with the following layout:

```
themes/
  my_theme/
    theme.json                 # Required — theme configuration
    fonts/
      title.TTF               # Title font (header bar)
      menu.ttf                # Menu body font (optional)
    images/
      frise.bmp               # Divider bar between panels
      battery.png             # Battery indicator icon
      target.bmp              # Stats icon — alive hosts
      port.bmp                # Stats icon — open ports
      vuln.bmp                # Stats icon — vulnerabilities
      cred.bmp                # Stats icon — credentials
      zombie.bmp              # Stats icon — compromised hosts
      data.bmp                # Stats icon — stolen data
      gold.bmp                # Corner stat — score
      level.bmp               # Corner stat — level
      networkkb.bmp           # Corner stat — known hosts
      attacks.bmp             # Corner stat — attacks count
      menu_bg.png             # Main menu background (optional)
      settings_bg.png         # Settings submenu background (optional)
      pause_bg.png            # Pause menu background — landscape (optional)
      pause_bg_portrait.png   # Pause menu background — portrait (optional)
      status/                 # Character animations per action
        IDLE/
          IDLE.png
          IDLE1.png
          IDLE2.png
          ...
        NetworkScanner/
          NetworkScanner.png
          NetworkScanner1.png
          ...
        SSHBruteforce/
          SSHBruteforce.png
          ...
        FTPBruteforce/
        TelnetBruteforce/
        SMBBruteforce/
        SQLBruteforce/
        RDPBruteforce/
        StealFilesSSH/
        StealFilesFTP/
        StealFilesSMB/
        StealFilesTelnet/
        StealDataSQL/
        NmapVulnScanner/
    comments/
      comments.json            # Commentary lines by action type
```

Any image or comment file you don't provide falls back to the default `loki` theme. System fonts fall back to `resources/fonts/`.

## Image Specifications

### Character Animation Frames (`images/status/`)

- **Recommended size**: 175x175 pixels (will be scaled to fit the display area)
- **Format**: PNG (with alpha transparency) or BMP
- **Naming**: Base name matches the action class, numbered sequentially: `IDLE.png`, `IDLE1.png`, `IDLE2.png`, ...
- **Alpha handling**: PNG images with transparency are automatically composited against the theme's `bg_color` and cached as BMP on first load. A loading screen is shown during initial cache generation.
- **Animation modes**: Set `animation_mode` in `theme.json`:
  - `"random"` — Picks a random frame each cycle (good for varied idle poses)
  - `"sequential"` — Plays frames in order for smooth animation

### Stats Icons (`images/`)

- **Recommended size**: Small icons, typically 16x16 to 24x24 pixels
- **Format**: BMP or PNG
- **Names**: `target`, `port`, `vuln`, `cred`, `zombie`, `data`, `gold`, `level`, `networkkb`, `attacks`, `battery`, `frise`

### Menu Backgrounds (`images/`)

- **Landscape**: 480x222 pixels
- **Portrait**: 222x480 pixels
- **Format**: PNG (recommended) or BMP
- **Files**: `menu_bg.png`, `settings_bg.png`, `pause_bg.png`, `pause_bg_portrait.png`
- If a background image bakes in the title text, set `show_menu_title`, `show_settings_title`, or `show_pause_title` to `false` in `theme.json` to hide the drawn title.

## theme.json Reference

A complete `theme.json` with all available fields:

```json
{
    "display_name": "MYTHEME",
    "menu_title": "My Theme",
    "web_title": "My Theme",

    "show_menu_title": true,
    "show_settings_title": true,
    "show_pause_title": true,

    "bg_color": [238, 147, 254],
    "text_color": [0, 0, 0],
    "accent_color": [0, 0, 0],
    "title_font_color": [0, 0, 0],
    "title_font_size": 26,
    "title_y_offset": 0,

    "animation_mode": "sequential",
    "image_display_delaymin": 1.5,
    "image_display_delaymax": 2,
    "comment_delaymin": 15,
    "comment_delaymax": 30,

    "moods": {
        "target": "Hunting",
        "swarm": "Frenzy",
        "recon": "Stealth"
    },

    "menu_colors": {
        "bg": [18, 22, 18],
        "title": [100, 190, 90],
        "selected": [130, 210, 110],
        "unselected": [140, 155, 140],
        "on": [90, 180, 80],
        "off": [100, 60, 60],
        "dim": [70, 85, 70],
        "warning": [180, 160, 50],
        "submenu": [100, 190, 90]
    },

    "pause_menu_colors": {
        "bg": [18, 22, 18],
        "text": [130, 210, 110],
        "accent": [60, 100, 60]
    },

    "web": {
        "bg_dark": "#0a120a",
        "bg_surface": "#121a12",
        "bg_elevated": "#1a251a",
        "accent": "#5ebd45",
        "accent_bright": "#7ed860",
        "accent_dim": "#3a8a28",
        "text_primary": "#d4e8d4",
        "text_secondary": "#7e9a7e",
        "text_muted": "#566b56",
        "border": "#263a26",
        "border_light": "#364a36",
        "glow": "0 0 12px rgba(94, 189, 69, 0.25)",
        "font_title": "'Viking', 'Georgia', serif",
        "nav_label_display": "Display"
    }
}
```

### Field Reference

#### Identity

| Field | Required | Description |
|-------|----------|-------------|
| `display_name` | Yes | Shown in the LCD header bar (e.g., "LOKI", "CLOWNSEC") |
| `menu_title` | Yes | Shown on the startup menu screen |
| `web_title` | Yes | Browser tab title for the web UI |

#### Title Visibility

| Field | Default | Description |
|-------|---------|-------------|
| `show_menu_title` | true | Draw title text on the main menu (set false if baked into `menu_bg.png`) |
| `show_settings_title` | true | Draw title text on the settings submenu |
| `show_pause_title` | true | Draw title text on the pause menu |

#### Colors

| Field | Format | Description |
|-------|--------|-------------|
| `bg_color` | `[R, G, B]` | LCD background color. Also used for PNG alpha compositing. |
| `text_color` | `[R, G, B]` | Primary text color on the LCD |
| `accent_color` | `[R, G, B]` | Accent color for dividers and highlights |
| `title_font_color` | `[R, G, B]` | Header title text color (overrides `text_color` for the header) |

#### Title Font

| Field | Default | Description |
|-------|---------|-------------|
| `title_font_size` | 26 | Title font size in pixels |
| `title_y_offset` | 0 | Pixel offset to nudge the header title vertically for centering with custom fonts |

#### Animation Timing

| Field | Default | Description |
|-------|---------|-------------|
| `animation_mode` | `"random"` | Frame selection mode: `"random"` or `"sequential"` |
| `image_display_delaymin` | 7 | Minimum seconds between animation frame changes |
| `image_display_delaymax` | 15 | Maximum seconds between animation frame changes |
| `comment_delaymin` | 15 | Minimum seconds between commentary updates |
| `comment_delaymax` | 30 | Maximum seconds between commentary updates |

These delay fields are optional. When provided, they override the global config values for this theme. To force global config values regardless of theme settings, enable `override_theme_delays` in the config.

#### Moods

| Field | Description |
|-------|-------------|
| `moods.target` | Label for the "Target" mood preset (aggressive, per-host attacks) |
| `moods.swarm` | Label for the "Swarm" mood preset (all attacks, spread across hosts) |
| `moods.recon` | Label for the "Recon" mood preset (scanning only, no attacks) |

#### Menu Colors

The `menu_colors` object controls the startup menu appearance:

| Key | Description |
|-----|-------------|
| `bg` | Menu background color |
| `title` | Title text color |
| `selected` | Currently highlighted menu item |
| `unselected` | Non-highlighted menu items |
| `on` | Toggle ON state color |
| `off` | Toggle OFF state color |
| `dim` | Grayed-out / disabled items |
| `warning` | Warning message color |
| `submenu` | Submenu header color |

#### Pause Menu Colors

The `pause_menu_colors` object controls the in-game pause menu:

| Key | Description |
|-----|-------------|
| `bg` | Pause menu background color |
| `text` | Pause menu text color |
| `accent` | Accent color for brightness bar and highlights |

#### Web UI Colors

The `web` object provides CSS custom properties for the web interface:

| Key | Description |
|-----|-------------|
| `bg_dark` | Page background |
| `bg_surface` | Card/panel background |
| `bg_elevated` | Elevated surface (modals, dropdowns) |
| `accent` | Primary accent color (buttons, links, active elements) |
| `accent_bright` | Hover/active state accent |
| `accent_dim` | Subtle accent (borders, inactive elements) |
| `text_primary` | Main text color |
| `text_secondary` | Secondary text (labels, descriptions) |
| `text_muted` | Muted text (timestamps, hints) |
| `border` | Default border color |
| `border_light` | Lighter border variant |
| `glow` | CSS box-shadow glow effect for accented elements |
| `font_title` | CSS font-family for the web UI title |
| `nav_label_display` | Custom label for the Display nav tab (e.g., "Loki", "Mirror") |

## Comments Format

The `comments/comments.json` file contains commentary lines grouped by action type. Each key maps to a list of strings that are randomly displayed on the LCD during that action:

```json
{
    "IDLE": ["Waiting for targets...", "Nothing to do..."],
    "NetworkScanner": ["Scanning the network...", "Looking for hosts..."],
    "SSHBruteforce": ["Trying SSH credentials...", "Knocking on port 22..."],
    "FTPBruteforce": ["Checking FTP access..."],
    "NmapVulnScanner": ["Running vulnerability scan..."],
    ...
}
```

### Supported Action Keys

`IDLE`, `NetworkScanner`, `NmapVulnScanner`, `SSHBruteforce`, `FTPBruteforce`, `TelnetBruteforce`, `SMBBruteforce`, `SQLBruteforce`, `RDPBruteforce`, `StealFilesSSH`, `StealFilesFTP`, `StealFilesSMB`, `StealFilesTelnet`, `StealDataSQL`, `LogStandalone`, `LogStandalone2`, `ZombifySSH`

## Tips

- Start by copying an existing theme folder and modifying it
- You don't need to provide every file — missing images and comments fall back to the `loki` theme
- Test your theme on the Pager by switching to it from the startup menu (live preview)
- Use `animation_mode: "sequential"` for smooth walk cycles or multi-frame animations
- Use `animation_mode: "random"` for varied idle poses or reaction images
- PNG alpha transparency is fully supported — the compositing is done automatically against `bg_color`
- Keep animation frame counts reasonable — more frames = more storage and longer initial cache time
- The web UI theme is applied via CSS custom properties, so colors update immediately when switching themes
