"""
Graphical startup menu for Pager Bjorn
Uses libpagerctl.so for fast native rendering in landscape mode (270, 480x222)
"""

import os
import sys
import subprocess
import time

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

# Font paths
FONTS_DIR = os.path.join(PAYLOAD_DIR, 'resources', 'fonts')
FONT_VIKING = os.path.join(FONTS_DIR, 'Viking.TTF')
FONT_DEJAVU = os.path.join(FONTS_DIR, 'DejaVuSansMono.ttf')

# TTF font sizes
TTF_SMALL = 14.0
TTF_MEDIUM = 18.0
TTF_LARGE = 24.0

# Loot directory paths
LOOT_DIR = "/mmc/root/loot/bjorn"
LOGS_DIR = os.path.join(LOOT_DIR, "logs")
CREDS_DIR = os.path.join(LOOT_DIR, "output", "crackedpwd")
STOLEN_DIR = os.path.join(LOOT_DIR, "output", "data_stolen")

from pagerctl import Pager

# Theme colors
TITLE_COLOR = Pager.rgb(100, 200, 255)  # Light blue
SELECTED_COLOR = Pager.GREEN
UNSELECTED_COLOR = Pager.WHITE
ON_COLOR = Pager.GREEN
OFF_COLOR = Pager.RED
DIM_COLOR = Pager.GRAY
WARNING_COLOR = Pager.rgb(255, 100, 0)
SUBMENU_COLOR = Pager.YELLOW


def detect_interfaces():
    """Detect network interfaces with IP addresses, returns list of {name, ip, subnet} dicts."""
    interfaces = []
    try:
        result = subprocess.run(['ip', 'addr'], capture_output=True, text=True, timeout=5)
        current_iface = None
        for line in result.stdout.split('\n'):
            if line and not line[0].isspace() and ':' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    current_iface = parts[1].strip()
            elif 'inet ' in line and current_iface:
                parts = line.strip().split()
                for i, p in enumerate(parts):
                    if p == 'inet' and i + 1 < len(parts):
                        cidr = parts[i + 1]
                        ip = cidr.split('/')[0]
                        if ip != '127.0.0.1':
                            interfaces.append({
                                'name': current_iface,
                                'ip': ip,
                                'subnet': cidr,
                            })
                        break
    except Exception:
        pass
    return interfaces


class BjornMenu:
    """Graphical startup menu for Bjorn on the Pager LCD."""

    def __init__(self, interfaces):
        self.interfaces = interfaces
        self.gfx = Pager()
        self.gfx.init()
        self.gfx.set_rotation(270)  # Landscape 480x222

    def cleanup(self):
        if hasattr(self, 'gfx'):
            self.gfx.cleanup()

    def _wait_button(self):
        """Wait for a button press using thread-safe event queue."""
        while True:
            self.gfx.poll_input()
            event = self.gfx.get_input_event()
            if event:
                button, event_type, timestamp = event
                if event_type == Pager.EVENT_PRESS:
                    if button == Pager.BTN_UP:
                        return 'UP'
                    if button == Pager.BTN_DOWN:
                        return 'DOWN'
                    if button == Pager.BTN_LEFT:
                        return 'LEFT'
                    if button == Pager.BTN_RIGHT:
                        return 'RIGHT'
                    if button == Pager.BTN_A:
                        return 'SELECT'
                    if button == Pager.BTN_B:
                        return 'BACK'
            else:
                time.sleep(0.016)

    def _draw_main_menu(self, selected, iface_idx, web_ui):
        """Draw the main menu screen."""
        self.gfx.clear(Pager.BLACK)

        # Title using Viking font
        self.gfx.draw_ttf_centered(0, "Pager Bjorn", TITLE_COLOR, FONT_VIKING, 48.0)

        # Menu items
        y = 68
        items = self._get_menu_items(iface_idx, web_ui)

        for i, item in enumerate(items):
            is_selected = (i == selected)

            if item.get('toggle'):
                # Toggle item: label + value
                label = item['label']
                value = item['value']
                value_color = item['value_color']
                label_color = SELECTED_COLOR if is_selected else UNSELECTED_COLOR

                # Calculate fixed positions using max value width for alignment
                max_value = item.get('max_value', value)
                label_width = self.gfx.ttf_width(label, FONT_DEJAVU, TTF_MEDIUM)
                max_value_width = self.gfx.ttf_width(max_value, FONT_DEJAVU, TTF_MEDIUM)
                total_width = label_width + 8 + max_value_width
                start_x = (480 - total_width) // 2
                self.gfx.draw_ttf(start_x, y, label, label_color, FONT_DEJAVU, TTF_MEDIUM)
                self.gfx.draw_ttf(start_x + label_width + 8, y, value, value_color, FONT_DEJAVU, TTF_MEDIUM)
            else:
                # Simple menu item
                color = SELECTED_COLOR if is_selected else UNSELECTED_COLOR
                self.gfx.draw_ttf_centered(y, item['label'], color, FONT_DEJAVU, TTF_MEDIUM)

            y += 25

        self.gfx.flip()

    def _get_menu_items(self, iface_idx, web_ui):
        """Build the list of menu items for drawing."""
        items = [{'label': 'Start Raid'}]

        # Interface selector
        if self.interfaces:
            iface = self.interfaces[iface_idx]
            iface_text = f"{iface['name']} ({iface['subnet']})"
        else:
            iface_text = "none"

        items.append({
            'toggle': True,
            'label': 'Interface:',
            'value': iface_text,
            'value_color': UNSELECTED_COLOR,
            'max_value': iface_text,  # Dynamic width
        })

        items.append({
            'toggle': True,
            'label': 'Web UI:',
            'value': 'ON :8000' if web_ui else 'OFF',
            'value_color': ON_COLOR if web_ui else OFF_COLOR,
            'max_value': 'ON :8000',
        })

        items.append({'label': 'Clear Data'})
        items.append({'label': 'Exit'})
        return items

    def show_main_menu(self):
        """Show the main menu. Returns config dict or None to exit."""
        selected = 0
        iface_idx = 0
        web_ui = True
        num_options = 5  # Start Raid, Interface, Web UI, Clear Data, Exit

        self._draw_main_menu(selected, iface_idx, web_ui)

        while True:
            btn = self._wait_button()

            if btn == 'UP':
                selected = (selected - 1) % num_options
                self._draw_main_menu(selected, iface_idx, web_ui)
            elif btn == 'DOWN':
                selected = (selected + 1) % num_options
                self._draw_main_menu(selected, iface_idx, web_ui)
            elif btn in ['LEFT', 'RIGHT']:
                if selected == 1 and self.interfaces:
                    # Cycle interface
                    if btn == 'RIGHT':
                        iface_idx = (iface_idx + 1) % len(self.interfaces)
                    else:
                        iface_idx = (iface_idx - 1) % len(self.interfaces)
                    self._draw_main_menu(selected, iface_idx, web_ui)
                elif selected == 2:
                    # Toggle web UI
                    web_ui = not web_ui
                    self._draw_main_menu(selected, iface_idx, web_ui)
            elif btn == 'SELECT':
                if selected == 0:
                    # Start Raid
                    if not self.interfaces:
                        self._show_message("No network!", WARNING_COLOR, "Connect to a network first", DIM_COLOR)
                        self._wait_button()
                        self._draw_main_menu(selected, iface_idx, web_ui)
                        continue
                    iface = self.interfaces[iface_idx]
                    return {
                        'interface': iface['name'],
                        'ip': iface['ip'],
                        'web_ui': web_ui,
                    }
                elif selected == 1 and self.interfaces:
                    # Cycle interface forward on select
                    iface_idx = (iface_idx + 1) % len(self.interfaces)
                    self._draw_main_menu(selected, iface_idx, web_ui)
                elif selected == 2:
                    web_ui = not web_ui
                    self._draw_main_menu(selected, iface_idx, web_ui)
                elif selected == 3:
                    # Clear Data submenu
                    self._show_clear_data_menu()
                    self._draw_main_menu(selected, iface_idx, web_ui)
                elif selected == 4:
                    # Exit
                    return None
            elif btn == 'BACK':
                return None

    def _show_message(self, text, color, subtext=None, subcolor=None):
        """Show a centered message on screen."""
        self.gfx.clear(Pager.BLACK)
        self.gfx.draw_ttf_centered(80, text, color, FONT_DEJAVU, TTF_LARGE)
        if subtext and subcolor:
            self.gfx.draw_ttf_centered(115, subtext, subcolor, FONT_DEJAVU, TTF_SMALL)
        self.gfx.flip()

    def _show_clear_data_menu(self):
        """Show the Clear Data submenu."""
        selected = 0
        options = ['Clear Logs', 'Clear Credentials', 'Clear Stolen Data', 'Clear All', 'Back']

        while True:
            self.gfx.clear(Pager.BLACK)
            self.gfx.draw_ttf_centered(12, "CLEAR DATA", SUBMENU_COLOR, FONT_DEJAVU, TTF_LARGE)

            y = 55
            for i, opt in enumerate(options):
                color = SELECTED_COLOR if i == selected else UNSELECTED_COLOR
                self.gfx.draw_ttf_centered(y, opt, color, FONT_DEJAVU, TTF_MEDIUM)
                y += 30

            self.gfx.flip()

            btn = self._wait_button()
            if btn == 'UP':
                selected = (selected - 1) % len(options)
            elif btn == 'DOWN':
                selected = (selected + 1) % len(options)
            elif btn == 'SELECT':
                if selected == 4:  # Back
                    return
                if selected == 0:
                    if self._confirm("Clear Logs?"):
                        self._clear_logs()
                elif selected == 1:
                    if self._confirm("Clear Credentials?"):
                        self._clear_credentials()
                elif selected == 2:
                    if self._confirm("Clear Stolen Data?"):
                        self._clear_stolen()
                elif selected == 3:
                    if self._confirm("Clear ALL Data?"):
                        self._clear_all()
            elif btn == 'BACK':
                return

    def _confirm(self, prompt):
        """Show YES/NO confirmation. Returns True if YES selected."""
        selected = 1  # Default to NO

        while True:
            self.gfx.clear(Pager.BLACK)
            self.gfx.draw_ttf_centered(60, prompt, WARNING_COLOR, FONT_DEJAVU, TTF_LARGE)

            center = 480 // 2
            yes_color = SELECTED_COLOR if selected == 0 else UNSELECTED_COLOR
            no_color = SELECTED_COLOR if selected == 1 else UNSELECTED_COLOR
            self.gfx.draw_ttf(center - 85, 115, "YES", yes_color, FONT_DEJAVU, TTF_MEDIUM)
            self.gfx.draw_ttf(center + 45, 115, "NO", no_color, FONT_DEJAVU, TTF_MEDIUM)
            self.gfx.flip()

            btn = self._wait_button()
            if btn in ['LEFT', 'RIGHT', 'UP', 'DOWN']:
                selected = 1 - selected
            elif btn == 'SELECT':
                return selected == 0
            elif btn == 'BACK':
                return False

    def _clear_logs(self):
        """Clear log files."""
        try:
            subprocess.run(['rm', '-rf', LOGS_DIR], timeout=5)
            os.makedirs(LOGS_DIR, exist_ok=True)
        except Exception:
            pass
        self._show_message("Logs Cleared!", ON_COLOR)
        time.sleep(0.5)

    def _clear_credentials(self):
        """Clear credential files."""
        try:
            for f in os.listdir(CREDS_DIR):
                if f.endswith('.csv'):
                    os.remove(os.path.join(CREDS_DIR, f))
        except Exception:
            pass
        self._show_message("Credentials Cleared!", ON_COLOR)
        time.sleep(0.5)

    def _clear_stolen(self):
        """Clear stolen data files."""
        try:
            subprocess.run(['rm', '-rf', STOLEN_DIR], timeout=5)
            os.makedirs(STOLEN_DIR, exist_ok=True)
        except Exception:
            pass
        self._show_message("Stolen Data Cleared!", ON_COLOR)
        time.sleep(0.5)

    def _clear_all(self):
        """Clear all Bjorn data."""
        # Each step independent so one failure doesn't skip the rest
        try:
            subprocess.run(['rm', '-rf', LOGS_DIR], timeout=5)
            os.makedirs(LOGS_DIR, exist_ok=True)
        except Exception:
            pass
        try:
            for f in os.listdir(CREDS_DIR):
                if f.endswith('.csv'):
                    os.remove(os.path.join(CREDS_DIR, f))
        except Exception:
            pass
        try:
            subprocess.run(['rm', '-rf', STOLEN_DIR], timeout=5)
            os.makedirs(STOLEN_DIR, exist_ok=True)
        except Exception:
            pass
        for name in ['netkb.csv', 'livestatus.csv']:
            try:
                path = os.path.join(LOOT_DIR, name)
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
        for subdir in ['output/scan_results', 'output/vulnerabilities', 'output/zombies', 'archives']:
            try:
                path = os.path.join(LOOT_DIR, subdir)
                subprocess.run(['rm', '-rf', path], timeout=5)
                os.makedirs(path, exist_ok=True)
            except Exception:
                pass
        self._show_message("All Data Cleared!", ON_COLOR)
        time.sleep(0.5)


def main():
    """Main entry point: menu loop -> launch Bjorn -> repeat."""
    menu = None
    try:
        while True:
            interfaces = detect_interfaces()

            # Give pagerctl time to release after Bjorn's os._exit()
            time.sleep(0.3)

            try:
                menu = BjornMenu(interfaces)
            except Exception as e:
                # Pagerctl init can fail after unclean exit - retry once
                time.sleep(1)
                try:
                    menu = BjornMenu(interfaces)
                except Exception:
                    sys.stderr.write(f"Failed to init display: {e}\n")
                    break

            result = menu.show_main_menu()

            if result is None:
                # Exit selected
                menu.cleanup()
                menu = None
                break

            # Show loading spinner before handing off to Bjorn
            menu._show_message("Starting Bjorn...", TITLE_COLOR, result['interface'] + " " + result['ip'], DIM_COLOR)
            menu.cleanup()
            menu = None

            # Launch Bjorn as subprocess
            env = os.environ.copy()
            env['BJORN_INTERFACE'] = result['interface']
            env['BJORN_IP'] = result['ip']
            env['BJORN_WEB_UI'] = 'on' if result['web_ui'] else 'off'

            proc = subprocess.run(
                ['python3', 'Bjorn.py'],
                cwd=PAYLOAD_DIR,
                env=env,
            )

            if proc.returncode == 42:
                # Handoff requested - .next_payload already written by display.py
                sys.exit(42)
            elif proc.returncode == 99:
                # Return to main menu - loop continues
                continue
            elif proc.returncode != 0:
                # Crash or unexpected exit - break out
                break

            # Exit Bjorn (code 0) — break out of loop
            break
    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.stderr.write(f"Menu error: {e}\n")
    finally:
        if menu:
            menu.cleanup()


if __name__ == "__main__":
    main()
