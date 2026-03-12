# App Handoff System

Pager payloads can seamlessly hand off to each other through a shared protocol. When a compatible payload is detected, an "Exit to [App]" option appears in the pause menu. This system is used by Loki, PagerGotchi, and any custom payload that follows this convention.

Each program runs alone — only one payload controls the display at a time.

## How It Works

1. Your payload discovers other apps by scanning for `launch_*.sh` scripts in its own directory
2. Each script declares a `# Title:` and `# Requires:` path in its header comments
3. If the required path exists on the device, the app appears in the pause menu
4. When the user selects an app, your payload writes the launcher path to `data/.next_payload` and exits with code **42**
5. Your `payload.sh` reads the file, runs the launcher script, and waits
6. When the launched app exits with code **42**, your payload loops back and restarts
7. Any other exit code breaks the loop and exits to the Pager service

## Exit Code Convention

| Exit Code | Meaning |
|-----------|---------|
| **0** | Normal exit — return to Pager service |
| **42** | Handoff — switch to another payload |
| **99** | Return to main menu (internal, handled by menu loop) |

## Adding a Launcher Script

To let **other apps** launch yours, create a `launch_<yourapp>.sh` file and place it in **their** payload directory. For example, Loki includes `launch_pagergotchi.sh`, and PagerGotchi includes `launch_loki.sh`.

### Launcher Script Format

```bash
#!/bin/bash
# Title: My App
# Requires: /root/payloads/user/reconnaissance/my_app

MY_APP_DIR="/root/payloads/user/reconnaissance/my_app"

if [ ! -d "$MY_APP_DIR" ]; then
    echo "My App not found at $MY_APP_DIR"
    exit 1
fi

# Setup environment
export PATH="/mmc/usr/bin:$MY_APP_DIR/bin:$PATH"
export PYTHONPATH="$MY_APP_DIR/lib:$MY_APP_DIR:$PYTHONPATH"
export LD_LIBRARY_PATH="/mmc/usr/lib:$MY_APP_DIR/lib:$LD_LIBRARY_PATH"

# Ensure pager service is stopped so we can use the display
if pgrep -x pineapple >/dev/null; then
    /etc/init.d/pineapplepager stop 2>/dev/null
    sleep 0.3
fi

cd "$MY_APP_DIR"
python3 main.py
exit $?
```

### Required Header Comments

- **`# Title:`** — Display name shown in the pause menu (e.g., "Exit to My App")
- **`# Requires:`** — Absolute path that must exist for the menu option to appear. If missing, the launcher is hidden. This prevents showing options for apps that aren't installed.

### Naming

- The filename must match `launch_*.sh` (e.g., `launch_myapp.sh`)
- Each app skips its own self-launcher automatically (e.g., Loki skips `launch_loki.sh`)

### Where to Place Launcher Scripts

Place your launcher script in the payload directory of every app you want to integrate with:

```
/root/payloads/user/reconnaissance/loki/launch_myapp.sh           # So Loki can launch your app
/root/payloads/user/reconnaissance/pagergotchi/launch_myapp.sh    # So Pagergotchi can launch your app
/root/payloads/user/reconnaissance/my_app/launch_loki.sh          # So your app can launch Loki
/root/payloads/user/reconnaissance/my_app/launch_pagergotchi.sh   # So your app can launch Pagergotchi
```

## Adding Handoff Support to Your Payload

### 1. payload.sh — The Handoff Loop

Your `payload.sh` needs a main loop that handles exit code 42 and the `.next_payload` file:

```bash
# Create data directory for handoff file
DATA_DIR="$PAYLOAD_DIR/data"
mkdir -p "$DATA_DIR" 2>/dev/null
NEXT_PAYLOAD_FILE="$DATA_DIR/.next_payload"

# Stop pager service before taking the display
/etc/init.d/pineapplepager stop 2>/dev/null
sleep 0.5

# Main loop — supports handoff to other payloads
while true; do
    cd "$PAYLOAD_DIR"
    python3 main.py
    EXIT_CODE=$?

    # Exit code 42 = hand off to another payload
    if [ "$EXIT_CODE" -eq 42 ] && [ -f "$NEXT_PAYLOAD_FILE" ]; then
        NEXT_SCRIPT=$(cat "$NEXT_PAYLOAD_FILE")
        rm -f "$NEXT_PAYLOAD_FILE"
        if [ -f "$NEXT_SCRIPT" ]; then
            bash "$NEXT_SCRIPT"
            # Loop back if launched app exits 42 (returning to us)
            [ $? -eq 42 ] && continue
        fi
    fi

    break
done
```

### 2. Python — Discover Launchers

Scan your payload directory for `launch_*.sh` files:

```python
import os
import glob

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

def discover_launchers():
    """Scan for launch_*.sh files. Returns list of (title, path) tuples."""
    launchers = []
    for path in sorted(glob.glob(os.path.join(PAYLOAD_DIR, 'launch_*.sh'))):
        basename = os.path.basename(path)
        if basename == 'launch_myapp.sh':  # Skip self-launcher
            continue
        title = None
        requires = None
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('# Title:'):
                    title = line[len('# Title:'):].strip()
                elif line.startswith('# Requires:'):
                    requires = line[len('# Requires:'):].strip()
                if title and requires:
                    break
        if not title:
            continue
        if requires and not os.path.isdir(requires):
            continue
        launchers.append((title, path))
    return launchers
```

### 3. Python — Trigger Handoff

When the user selects an app from the pause menu, write the launcher path and exit with code 42:

```python
import os
import sys

def handoff_to(launcher_path):
    """Write next payload path and exit with code 42."""
    data_dir = os.path.join(PAYLOAD_DIR, 'data')
    os.makedirs(data_dir, exist_ok=True)
    next_payload_file = os.path.join(data_dir, '.next_payload')
    with open(next_payload_file, 'w') as f:
        f.write(launcher_path)
    sys.exit(42)
```

### 4. Pause Menu — Toggle Launcher

The pause menu shows discovered launchers as a single toggle item. When there are multiple launchers, LEFT/RIGHT cycles through them. SELECT launches the currently displayed app.

```python
launchers = discover_launchers()
launcher_idx = 0

# In your menu rendering:
if launchers:
    title, path = launchers[launcher_idx]
    # Draw "EXIT TO {title}" button

# LEFT/RIGHT cycles when launcher is selected and multiple exist:
if len(launchers) > 1:
    launcher_idx = (launcher_idx + 1) % len(launchers)
    title, path = launchers[launcher_idx]

# On SELECT:
if launchers:
    title, path = launchers[launcher_idx]
    handoff_to(path)
```

## Bidirectional Handoff Example

For two apps (App A and App B) to switch between each other:

**In App A's directory:**
```
my_app_a/
├── payload.sh              # Has handoff loop
├── main.py                 # Your app with pause menu + discover_launchers()
├── launch_appb.sh          # So App A can launch App B
└── data/.next_payload      # Written at runtime (not committed)
```

**In App B's directory:**
```
my_app_b/
├── payload.sh              # Has handoff loop
├── main.py                 # Your app with pause menu + discover_launchers()
├── launch_appa.sh          # So App B can launch App A
└── data/.next_payload      # Written at runtime (not committed)
```

The flow:
1. User starts App A from the Pager launcher
2. App A's `payload.sh` runs `main.py`
3. User opens pause menu, sees "Exit to App B", selects it
4. App A writes `launch_appb.sh` path to `.next_payload`, exits with code 42
5. App A's `payload.sh` reads the file, runs `launch_appb.sh`
6. App B starts and takes the display
7. User opens App B's pause menu, sees "Exit to App A", selects it
8. App B exits with code 42 → `launch_appb.sh` exits with code 42
9. App A's `payload.sh` sees exit code 42, loops back, restarts `main.py`

## Reference Implementations

- **Loki** — `display.py:discover_launchers()`, `payload.sh` handoff loop
- **PagerGotchi** — `pwnagotchi_port/ui/view.py:discover_launchers()`, `payload.sh` handoff loop
