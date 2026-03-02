#display.py
# Description:
# Pager LCD display module for Bjorn.
# Supports portrait (222x480) and landscape (480x222) orientations.
# Layout coordinates defined in DEFAULT_LAYOUTS, overridable by themes.

import copy
import threading
import time
import os
import sys
import signal
import logging
import random
import glob
import subprocess
import csv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pagerctl import Pager
from init_shared import shared_data
from comment import Commentaireia
from logger import Logger

logger = Logger(name="display.py", level=logging.INFO)

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Layout Registry
# ---------------------------------------------------------------------------
# Absolute pixel coordinates for every UI element in each orientation.
# Portrait values preserve the exact look from the original scale-factor code
# (sx=222/122, sy=480/250).  Landscape uses a two-column layout: header +
# character + corner-stats on the left (233 px), stats/status/dialogue on
# the right (247 px).
# ---------------------------------------------------------------------------

DEFAULT_LAYOUTS = {
    "portrait": {
        "screen_w": 222,
        "screen_h": 480,
        "header": {
            "x": 0, "y": 0, "w": 222, "h": 38,
            "title_y": 9, "title_font_size": 26,
        },
        "stats_grid": {
            "x": 0, "y": 42, "w": 222, "h": 76,
            "cols": 3, "rows": 2,
            "icon_size": 30, "font_size": 23,
        },
        "status_area": {
            "x": 0, "y": 119, "w": 222, "h": 53,
            "icon_size": 46,
            "main_font_size": 23, "sub_font_size": 19,
        },
        "dialogue": {
            "x": 0, "y": 172, "w": 222, "h": 134,
            "font_size": 23, "line_height": 26,
            "max_lines": 4, "margin": 8,
        },
        "frise": {
            "x": 0, "y": 297, "w": 222, "h": 23,
        },
        "character": {
            "x": 38, "y": 327, "w": 145, "h": 145,
        },
        "corner_stats": {
            "area_x": 0, "area_w": 222,
            "icon_size": 34, "font_size": 23,
            "top_y": 325,
            "bottom_y": 409,
        },
    },
    "landscape": {
        "screen_w": 480,
        "screen_h": 222,
        # Left panel: 233px
        "header": {
            "x": 0, "y": 0, "w": 233, "h": 40,
            "title_y": 9, "title_font_size": 26,
        },
        "frise": {
            "x": 233, "y": 0, "w": 23, "h": 222,
        },
        # Right panel: x=251, w=229 (unchanged)
        "stats_grid": {
            "x": 255, "y": 0, "w": 225, "h": 76,
            "cols": 3, "rows": 2,
            "icon_size": 30, "font_size": 23,
        },
        "status_area": {
            "x": 251, "y": 76, "w": 229, "h": 53,
            "icon_size": 46,
            "main_font_size": 23, "sub_font_size": 19,
        },
        "dialogue": {
            "x": 253, "y": 129, "w": 227, "h": 93,
            "font_size": 23, "line_height": 21,
            "max_lines": 4, "margin": 4,
        },
        # Character in left panel below header (square aspect ratio)
        "character": {
            "x": 29, "y": 47, "w": 175, "h": 175,
        },
        # Corner stats — same size as stats grid icons (30px / 23pt)
        "corner_stats": {
            "area_x": 0, "area_w": 233,
            "icon_size": 30, "font_size": 23,
            "top_y": 45,
            "bottom_y": 165,
        },
    },
}


def discover_launchers():
    """Scan PAYLOAD_DIR for launch_*.sh scripts with valid # Requires: paths.
    Returns list of (title, path) tuples. Skips self-launchers (launch_bjorn.sh)."""
    launchers = []
    pattern = os.path.join(PAYLOAD_DIR, 'launch_*.sh')
    matches = sorted(glob.glob(pattern))
    logger.info(f"discover_launchers: PAYLOAD_DIR={PAYLOAD_DIR} pattern={pattern} matches={matches}")
    for path in matches:
        basename = os.path.basename(path)
        if basename == 'launch_bjorn.sh':
            continue
        title = None
        requires = None
        try:
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('# Title:'):
                        title = line[len('# Title:'):].strip()
                    elif line.startswith('# Requires:'):
                        requires = line[len('# Requires:'):].strip()
                    if title and requires:
                        break
        except Exception as e:
            logger.error(f"discover_launchers: error reading {path}: {e}")
            continue
        logger.info(f"discover_launchers: {basename} title={title} requires={requires} isdir={os.path.isdir(requires) if requires else 'N/A'}")
        if not title:
            continue
        if requires and not os.path.isdir(requires):
            continue
        launchers.append((title, path))
    logger.info(f"discover_launchers: returning {launchers}")
    return launchers


class Display:
    """Pager display with portrait/landscape orientation support."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.config = self.shared_data.config
        self.shared_data.bjornstatustext2 = "Awakening..."
        self.commentaire_ia = Commentaireia()
        self.semaphore = threading.Semaphore(10)

        # --- Determine rotation ---
        config_rotation = self.config.get('screen_rotation', 270)
        preferred = getattr(self.shared_data, 'theme_preferred_orientation', None)
        if preferred == "portrait":
            rotation = 0
        elif preferred == "landscape":
            rotation = 270
        else:
            rotation = config_rotation

        # Initialize pagerctl
        try:
            logger.info("Initializing pagerctl display...")
            self.pager = Pager()
            self.pager.init()
            self.pager.set_rotation(rotation)

            self.width = self.pager.width
            self.height = self.pager.height
            self.orientation = "landscape" if rotation == 270 else "portrait"
            logger.info(f"Pager display initialized: {self.width}x{self.height} ({self.orientation})")

            self.shared_data.width = self.width
            self.shared_data.height = self.height

        except Exception as e:
            logger.error(f"Error initializing pagerctl: {e}")
            raise

        # Build the active layout (defaults + theme overrides)
        self.layout = self._build_layout()

        # Colors from theme (bg, text, accent) with hardcoded fallbacks
        bg = self.shared_data.theme_bg_color
        txt = self.shared_data.theme_text_color
        acc = self.shared_data.theme_accent_color
        self.BG_COLOR = self.pager.rgb(bg[0], bg[1], bg[2])
        self.TEXT_COLOR = self.pager.rgb(txt[0], txt[1], txt[2])
        self.ACCENT_COLOR = self.pager.rgb(acc[0], acc[1], acc[2])
        tc = self.shared_data.theme_title_font_color
        self.TITLE_COLOR = self.pager.rgb(tc[0], tc[1], tc[2]) if tc else self.TEXT_COLOR
        # Keep BLACK/WHITE for menu dialogs (always white-on-black)
        self.BLACK = self.pager.BLACK
        self.WHITE = self.pager.WHITE

        # Fonts
        self.font_arial = self.shared_data.font_arial_path
        self.font_viking = self.shared_data.font_viking_path

        # Current animation frame
        self.main_image_path = None
        self.manual_mode_txt = "M" if self.shared_data.manual_mode else "A"
        self.last_led_status = None
        self.dialog_showing = False  # Flag to pause display updates during dialogs
        self._cleaned_up = False

        # Brightness/dim settings
        self.screen_brightness = getattr(self.shared_data, 'screen_brightness', 80)
        self.screen_dim_brightness = getattr(self.shared_data, 'screen_dim_brightness', 20)
        self.screen_dim_timeout = getattr(self.shared_data, 'screen_dim_timeout', 60)
        self.last_activity_time = time.time()
        self.is_dimmed = False

        # Set initial brightness
        try:
            self.pager.set_brightness(self.screen_brightness)
            logger.info(f"Screen brightness set to {self.screen_brightness}%")
        except Exception as e:
            logger.debug(f"Could not set brightness: {e}")

        self.start_threads()
        logger.info("Display initialization complete.")

    # ------------------------------------------------------------------
    # Layout builder
    # ------------------------------------------------------------------

    def _build_layout(self):
        """Build active layout by merging DEFAULT_LAYOUTS with theme overrides."""
        base = copy.deepcopy(DEFAULT_LAYOUTS[self.orientation])

        # Get theme overrides for current orientation
        if self.orientation == "portrait":
            overrides = getattr(self.shared_data, 'theme_layout_portrait', {})
        else:
            overrides = getattr(self.shared_data, 'theme_layout_landscape', {})

        if not overrides:
            return base

        # Merge: only override specified properties
        for element_name, props in overrides.items():
            if element_name in base and isinstance(props, dict):
                base[element_name].update(props)

        return base

    # ------------------------------------------------------------------
    # Threads
    # ------------------------------------------------------------------

    def start_threads(self):
        threading.Thread(target=self.update_main_image, daemon=True).start()
        threading.Thread(target=self.schedule_update_shared_data, daemon=True).start()
        threading.Thread(target=self.schedule_update_vuln_count, daemon=True).start()
        threading.Thread(target=self.handle_input_loop, daemon=True).start()
        threading.Thread(target=self.poll_battery, daemon=True).start()

    def update_main_image(self):
        while not self.shared_data.display_should_exit:
            try:
                self.shared_data.update_image_randomizer()
                if self.shared_data.current_image_path:
                    self.main_image_path = self.shared_data.current_image_path
                dmin, dmax = self.shared_data.get_effective_delays()
                if getattr(self.shared_data, 'animation_mode', 'random') == 'sequential':
                    delay = dmin
                else:
                    delay = random.uniform(dmin, dmax)
                time.sleep(delay)
            except Exception as e:
                logger.error(f"Error in update_main_image: {e}")
                time.sleep(1)

    def schedule_update_shared_data(self):
        while not self.shared_data.display_should_exit:
            self.update_shared_data()
            time.sleep(25)

    def schedule_update_vuln_count(self):
        while not self.shared_data.display_should_exit:
            self.update_vuln_count()
            time.sleep(30)

    def poll_battery(self):
        """Poll battery level and charging status every 30 seconds."""
        while not self.shared_data.display_should_exit:
            try:
                self.shared_data.battery_level = self.shared_data.get_battery_level()
                self.shared_data.battery_charging = self.shared_data.get_battery_charging()
            except Exception as e:
                logger.debug(f"Battery poll error: {e}")
            time.sleep(30)

    # ------------------------------------------------------------------
    # Screen brightness / dim
    # ------------------------------------------------------------------

    def wake_screen(self):
        """Wake screen from dim state."""
        if self.is_dimmed:
            try:
                self.pager.set_brightness(self.screen_brightness)
                self.is_dimmed = False
                logger.debug("Screen woken from dim")
            except Exception as e:
                logger.debug(f"Could not wake screen: {e}")
        self.last_activity_time = time.time()

    def dim_screen(self):
        """Dim the screen to save battery."""
        if not self.is_dimmed:
            try:
                self.pager.set_brightness(self.screen_dim_brightness)
                self.is_dimmed = True
                logger.debug("Screen dimmed")
            except Exception as e:
                logger.debug(f"Could not dim screen: {e}")

    def check_dim_timeout(self):
        """Check if screen should be dimmed due to inactivity."""
        if self.screen_dim_timeout > 0 and not self.is_dimmed:
            if time.time() - self.last_activity_time > self.screen_dim_timeout:
                self.dim_screen()

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------

    def handle_input_loop(self):
        """Handle button input - Red button shows pause menu."""
        logger.info("Input handler: Monitoring for button presses")
        while not self.shared_data.display_should_exit:
            try:
                # Wait for button press (blocking)
                button = self.pager.wait_button()

                # Any button press wakes the screen and resets activity timer
                self.wake_screen()

                # Red button (B) - show pause menu
                if button & self.pager.BTN_B:
                    logger.info("Red button pressed - showing pause menu")
                    action = self.show_exit_confirmation()
                    if action is None:
                        logger.info("Back to scanning")
                        continue
                    logger.info(f"Menu action: exit code {action}")
                    self.shared_data.should_exit = True
                    self.shared_data.display_should_exit = True
                    self.shared_data.orchestrator_should_exit = True
                    if action == 42:
                        # Write .next_payload for handoff
                        data_dir = os.path.join(PAYLOAD_DIR, 'data')
                        os.makedirs(data_dir, exist_ok=True)
                        next_payload_path = os.path.join(data_dir, '.next_payload')
                        with open(next_payload_path, 'w') as f:
                            f.write(self._handoff_launcher_path)
                        logger.info(f"Wrote .next_payload: {self._handoff_launcher_path}")
                    self.cleanup()
                    # Kill any running nmap subprocesses before exit
                    try:
                        subprocess.run(['killall', 'nmap'], capture_output=True, timeout=5)
                    except Exception:
                        pass
                    os._exit(action)
            except Exception as e:
                logger.error(f"Error in input handler: {e}")
                time.sleep(1.0)

    # ------------------------------------------------------------------
    # Pause menu (dispatch)
    # ------------------------------------------------------------------

    def show_exit_confirmation(self):
        """Show pause menu with brightness control and exit options.
        Returns: None=back, 99=main menu, 42=launcher handoff, 0=exit bjorn."""
        if self.orientation == "landscape":
            return self._pause_menu_landscape()
        else:
            return self._pause_menu_portrait()

    def _pause_menu_portrait(self):
        """Portrait pause menu - buttons remapped for sideways holding.
        Physical DOWN/UP = brightness, LEFT/RIGHT = navigate."""
        self.dialog_showing = True
        time.sleep(0.2)

        current_brightness = self.pager.get_brightness()
        if current_brightness < 0:
            current_brightness = self.screen_brightness

        green_color = self.pager.rgb(0, 150, 0)
        yellow_color = self.pager.rgb(180, 150, 0)
        blue_color = self.pager.rgb(50, 100, 220)
        red_color = self.pager.rgb(200, 0, 0)

        options = [
            ("MAIN MENU", yellow_color, 99),
        ]
        launchers = discover_launchers()
        for title, path in launchers:
            options.append((f"> {title}", blue_color, (42, path)))
        options.append(("EXIT BJORN", red_color, 0))

        num_options = len(options)
        selected = 0

        # Scale factors for portrait menu sizing
        sy = self.height / 250.0

        def draw_menu():
            self.pager.fill_rect(0, 0, self.width, self.height, self.BG_COLOR)

            box_y = int(self.height * 0.10)
            box_h = int(self.height * 0.80)
            self.pager.fill_rect(10, box_y, self.width - 20, box_h, self.BG_COLOR)
            self.pager.rect(10, box_y, self.width - 20, box_h, self.TEXT_COLOR)
            self.pager.rect(12, box_y + 2, self.width - 24, box_h - 4, self.TEXT_COLOR)

            title_y = box_y + 15
            self.pager.draw_ttf_centered(title_y, "MENU", self.TEXT_COLOR, self.font_viking, int(12 * sy))

            bright_y = box_y + int(30 * sy)
            self.pager.draw_ttf_centered(bright_y, "BRIGHTNESS", self.TEXT_COLOR, self.font_arial, int(9 * sy))

            bar_y = bright_y + int(22 * sy)
            bar_x = 30
            bar_w = self.width - 60
            bar_h = int(12 * sy)
            self.pager.fill_rect(bar_x, bar_y, bar_w, bar_h, self.ACCENT_COLOR)
            fill_w = int(bar_w * current_brightness / 100)
            self.pager.fill_rect(bar_x, bar_y, fill_w, bar_h, self.TEXT_COLOR)
            self.pager.rect(bar_x, bar_y, bar_w, bar_h, self.TEXT_COLOR)

            pct_y = bar_y + bar_h + 5
            self.pager.draw_ttf_centered(pct_y, f"{current_brightness}%", self.TEXT_COLOR, self.font_arial, int(10 * sy))

            btn_w = 120
            btn_h = 28
            btn_x = (self.width - btn_w) // 2
            btn_gap = 8
            font_size = int(8 * sy)
            first_btn_y = pct_y + int(18 * sy)

            for i, (label, color, _action) in enumerate(options):
                btn_y = first_btn_y + i * (btn_h + btn_gap)
                if i == selected:
                    self.pager.fill_rect(btn_x - 4, btn_y - 4, btn_w + 8, btn_h + 8, self.TEXT_COLOR)
                self.pager.fill_rect(btn_x, btn_y, btn_w, btn_h, color)
                text_w = self.pager.ttf_width(label, self.font_arial, font_size)
                text_x = btn_x + (btn_w - text_w) // 2
                text_y = btn_y + (btn_h - font_size) // 2
                self.pager.draw_ttf(text_x, text_y, label, self.BG_COLOR, self.font_arial, font_size)

            self.pager.flip()

        draw_menu()

        while True:
            button = self.pager.wait_button()

            if button & self.pager.BTN_DOWN:
                # Physical DOWN = Visual LEFT = Decrease brightness
                current_brightness = max(20, current_brightness - 10)
                self.pager.set_brightness(current_brightness)
                self.screen_brightness = current_brightness
                draw_menu()
            elif button & self.pager.BTN_UP:
                # Physical UP = Visual RIGHT = Increase brightness
                current_brightness = min(100, current_brightness + 10)
                self.pager.set_brightness(current_brightness)
                self.screen_brightness = current_brightness
                draw_menu()
            elif button & self.pager.BTN_LEFT:
                # Physical LEFT = Visual UP = Move selection up
                selected = (selected - 1) % num_options
                draw_menu()
            elif button & self.pager.BTN_RIGHT:
                # Physical RIGHT = Visual DOWN = Move selection down
                selected = (selected + 1) % num_options
                draw_menu()
            elif button & self.pager.BTN_A:
                self.dialog_showing = False
                action = options[selected][2]
                if isinstance(action, tuple):
                    self._handoff_launcher_path = action[1]
                    return 42
                else:
                    return action
            elif button & self.pager.BTN_B:
                self.dialog_showing = False
                return None

    def _pause_menu_landscape(self):
        """Landscape pause menu - natural button directions.
        UP/DOWN = navigate, LEFT/RIGHT = brightness."""
        self.dialog_showing = True
        time.sleep(0.2)

        current_brightness = self.pager.get_brightness()
        if current_brightness < 0:
            current_brightness = self.screen_brightness

        green_color = self.pager.rgb(0, 150, 0)
        yellow_color = self.pager.rgb(180, 150, 0)
        blue_color = self.pager.rgb(50, 100, 220)
        red_color = self.pager.rgb(200, 0, 0)

        options = [
            ("MAIN MENU", yellow_color, 99),
        ]
        launchers = discover_launchers()
        for title, path in launchers:
            options.append((f"> {title}", blue_color, (42, path)))
        options.append(("EXIT BJORN", red_color, 0))

        num_options = len(options)
        selected = 0

        def draw_menu():
            self.pager.fill_rect(0, 0, self.width, self.height, self.BG_COLOR)

            # Dialog box
            box_x, box_y = 10, 10
            box_w, box_h = self.width - 20, self.height - 20
            self.pager.fill_rect(box_x, box_y, box_w, box_h, self.BG_COLOR)
            self.pager.rect(box_x, box_y, box_w, box_h, self.TEXT_COLOR)
            self.pager.rect(box_x + 2, box_y + 2, box_w - 4, box_h - 4, self.TEXT_COLOR)

            # Title
            title_fs = 26
            title_w = self.pager.ttf_width("MENU", self.font_viking, title_fs)
            self.pager.draw_ttf((self.width - title_w) // 2, 16, "MENU", self.TEXT_COLOR, self.font_viking, title_fs)

            # Brightness section
            lbl_fs = 16
            lbl_w = self.pager.ttf_width("BRIGHTNESS", self.font_arial, lbl_fs)
            self.pager.draw_ttf((self.width - lbl_w) // 2, 46, "BRIGHTNESS", self.TEXT_COLOR, self.font_arial, lbl_fs)

            bar_y = 66
            bar_x = 40
            bar_w = self.width - 80
            bar_h = 16
            self.pager.fill_rect(bar_x, bar_y, bar_w, bar_h, self.ACCENT_COLOR)
            fill_w = int(bar_w * current_brightness / 100)
            self.pager.fill_rect(bar_x, bar_y, fill_w, bar_h, self.TEXT_COLOR)
            self.pager.rect(bar_x, bar_y, bar_w, bar_h, self.TEXT_COLOR)

            pct_text = f"{current_brightness}%"
            pct_fs = 16
            pct_w = self.pager.ttf_width(pct_text, self.font_arial, pct_fs)
            self.pager.draw_ttf((self.width - pct_w) // 2, 86, pct_text, self.TEXT_COLOR, self.font_arial, pct_fs)

            # Menu buttons - vertical stack
            btn_w = 200
            btn_h = 32
            btn_x = (self.width - btn_w) // 2
            btn_gap = 8
            font_size = 18
            first_btn_y = 112

            for i, (label, color, _action) in enumerate(options):
                btn_y = first_btn_y + i * (btn_h + btn_gap)
                if i == selected:
                    self.pager.fill_rect(btn_x - 3, btn_y - 3, btn_w + 6, btn_h + 6, self.TEXT_COLOR)
                self.pager.fill_rect(btn_x, btn_y, btn_w, btn_h, color)
                text_w = self.pager.ttf_width(label, self.font_arial, font_size)
                text_x = btn_x + (btn_w - text_w) // 2
                text_y = btn_y + (btn_h - font_size) // 2
                self.pager.draw_ttf(text_x, text_y, label, self.BG_COLOR, self.font_arial, font_size)

            self.pager.flip()

        draw_menu()

        while True:
            button = self.pager.wait_button()

            if button & self.pager.BTN_UP:
                selected = (selected - 1) % num_options
                draw_menu()
            elif button & self.pager.BTN_DOWN:
                selected = (selected + 1) % num_options
                draw_menu()
            elif button & self.pager.BTN_LEFT:
                current_brightness = max(20, current_brightness - 10)
                self.pager.set_brightness(current_brightness)
                self.screen_brightness = current_brightness
                draw_menu()
            elif button & self.pager.BTN_RIGHT:
                current_brightness = min(100, current_brightness + 10)
                self.pager.set_brightness(current_brightness)
                self.screen_brightness = current_brightness
                draw_menu()
            elif button & self.pager.BTN_A:
                self.dialog_showing = False
                action = options[selected][2]
                if isinstance(action, tuple):
                    self._handoff_launcher_path = action[1]
                    return 42
                else:
                    return action
            elif button & self.pager.BTN_B:
                self.dialog_showing = False
                return None

    # ------------------------------------------------------------------
    # Data updates
    # ------------------------------------------------------------------

    def update_vuln_count(self):
        with self.semaphore:
            try:
                if not os.path.exists(self.shared_data.vuln_summary_file):
                    with open(self.shared_data.vuln_summary_file, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(["IP", "Hostname", "MAC Address", "Port", "Vulnerabilities"])
                    self.shared_data.vulnnbr = 0
                else:
                    with open(self.shared_data.vuln_summary_file, 'r') as file:
                        reader = csv.DictReader(file)
                        total_vulns = 0
                        for row in reader:
                            vulnerabilities = row.get("Vulnerabilities", "").strip()
                            if vulnerabilities:
                                total_vulns += len([v for v in vulnerabilities.split("; ") if v.strip()])
                        self.shared_data.vulnnbr = total_vulns
            except Exception as e:
                logger.error(f"Error in update_vuln_count: {e}")

    def update_shared_data(self):
        with self.semaphore:
            try:
                if os.path.exists(self.shared_data.livestatusfile):
                    with open(self.shared_data.livestatusfile, 'r') as file:
                        reader = csv.DictReader(file)
                        for row in reader:
                            self.shared_data.portnbr = int(row.get('Total Open Ports', 0) or 0)
                            self.shared_data.targetnbr = int(row.get('Alive Hosts Count', 0) or 0)
                            self.shared_data.networkkbnbr = int(row.get('All Known Hosts Count', 0) or 0)
                            break

                crackedpw_files = glob.glob(f"{self.shared_data.crackedpwddir}/*.csv")
                total_passwords = 0
                for filepath in crackedpw_files:
                    try:
                        with open(filepath, 'r') as f:
                            reader = csv.reader(f)
                            next(reader, None)
                            total_passwords += sum(1 for _ in reader)
                    except:
                        pass
                self.shared_data.crednbr = total_passwords

                total_data = sum([len(files) for r, d, files in os.walk(self.shared_data.datastolendir)])
                self.shared_data.datanbr = total_data

                total_zombies = sum([len(files) for r, d, files in os.walk(self.shared_data.zombiesdir)])
                self.shared_data.zombiesnbr = total_zombies

                # attacksnbr is incremented by orchestrator when attacks are performed
                # Don't count action module files here - that's not attacks performed

                self.shared_data.update_stats()
                self.shared_data.manual_mode = self.is_manual_mode()
                self.manual_mode_txt = "M" if self.shared_data.manual_mode else "A"
                self.shared_data.wifi_connected = self.is_wifi_connected()

            except FileNotFoundError as e:
                logger.debug(f"Data file not ready: {e}")
            except Exception as e:
                logger.error(f"Error updating shared data: {e}")

    def display_comment(self, status):
        comment = self.commentaire_ia.get_commentaire(status)
        if comment:
            self.shared_data.bjornsay = comment
            self.shared_data.bjornstatustext = self.shared_data.bjornorch_status

    def is_wifi_connected(self):
        try:
            result = subprocess.run(['iwgetid', '-r'], capture_output=True, text=True, timeout=5)
            return bool(result.stdout.strip())
        except:
            return False

    def is_manual_mode(self):
        return self.shared_data.manual_mode

    # ------------------------------------------------------------------
    # LEDs
    # ------------------------------------------------------------------

    def update_leds(self, status):
        if status == self.last_led_status:
            return
        self.last_led_status = status
        try:
            if status == "IDLE":
                self.pager.led_dpad("up", 0x000033)
                self.pager.led_dpad("down", 0x000033)
                self.pager.led_dpad("left", 0x000033)
                self.pager.led_dpad("right", 0x000033)
            elif "Scanner" in status or "Scan" in status:
                self.pager.led_dpad("up", 0x00FFFF)
                self.pager.led_dpad("down", 0x003333)
                self.pager.led_dpad("left", 0x003333)
                self.pager.led_dpad("right", 0x00FFFF)
            elif "Bruteforce" in status:
                self.pager.led_dpad("up", 0xFF0000)
                self.pager.led_dpad("down", 0xFF0000)
                self.pager.led_dpad("left", 0x330000)
                self.pager.led_dpad("right", 0x330000)
            elif "Steal" in status:
                self.pager.led_dpad("up", 0xFFFF00)
                self.pager.led_dpad("down", 0x333300)
                self.pager.led_dpad("left", 0xFFFF00)
                self.pager.led_dpad("right", 0x333300)
            else:
                self.pager.led_dpad("up", 0x00FF00)
                self.pager.led_dpad("down", 0x003300)
                self.pager.led_dpad("left", 0x003300)
                self.pager.led_dpad("right", 0x00FF00)
        except Exception as e:
            logger.debug(f"LED update error: {e}")

    # ------------------------------------------------------------------
    # Text helpers
    # ------------------------------------------------------------------

    def _wrap_text_pixel(self, text, font_path, font_size, max_width):
        """Wrap text based on actual pixel width using ttf_width."""
        words = text.split()
        lines = []
        line = ''
        for word in words:
            test = line + (' ' if line else '') + word
            if self.pager.ttf_width(test, font_path, font_size) <= max_width:
                line = test
            else:
                if line:
                    lines.append(line)
                # If a single word is wider than max, just add it anyway
                line = word
        if line:
            lines.append(line)
        return lines

    def sanitize_text(self, text):
        """Fix encoding issues with special characters."""
        if not text:
            return text
        replacements = {
            '\u2018': "'",  # Left single quote
            '\u2019': "'",  # Right single quote (apostrophe)
            '\u201c': '"',  # Left double quote
            '\u201d': '"',  # Right double quote
            '\u2013': '-',  # En dash
            '\u2014': '-',  # Em dash
            '\u2026': '...', # Ellipsis
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    # ------------------------------------------------------------------
    # Icon helpers
    # ------------------------------------------------------------------

    def draw_icon(self, x, y, icon_name):
        """Draw icon from static images."""
        icon_path = self.shared_data.static_images.get(icon_name)
        if icon_path and os.path.exists(icon_path):
            try:
                self.pager.draw_image_file(x, y, icon_path)
                return True
            except Exception as e:
                logger.debug(f"Could not draw icon {icon_name}: {e}")
        return False

    def draw_icon_scaled(self, x, y, w, h, icon_name):
        """Draw icon scaled to size."""
        icon_path = self.shared_data.static_images.get(icon_name)
        if icon_path and os.path.exists(icon_path):
            try:
                self.pager.draw_image_file_scaled(x, y, w, h, icon_path)
                return True
            except Exception as e:
                logger.debug(f"Could not draw scaled icon {icon_name}: {e}")
        return False

    # ------------------------------------------------------------------
    # Draw methods (layout-driven)
    # ------------------------------------------------------------------

    def draw_header(self):
        """Header: left-aligned title + right-aligned battery indicator."""
        L = self.layout["header"]
        self.pager.fill_rect(L["x"], L["y"], L["w"], L["h"], self.BG_COLOR)
        if self.orientation == "landscape":
            # Extend line across full screen width — frise draws on top
            self.pager.hline(0, L["y"] + L["h"] - 1, self.layout["screen_w"], self.TEXT_COLOR)
        else:
            self.pager.hline(L["x"], L["y"] + L["h"] - 1, L["w"], self.TEXT_COLOR)

        title = self.shared_data.display_name
        fs = getattr(self.shared_data, 'theme_title_font_size', None) or L["title_font_size"]
        tx = L["x"] + 6
        margin = 4

        # Battery layout — compute icon position first so we can fit the title
        bat = self.shared_data.battery_level
        icon_h = 22
        icon_w = int(icon_h * 1.8)  # battery icon aspect ratio ~1.8:1
        if bat is not None:
            icon_x = L["x"] + L["w"] - icon_w - margin
            # Shrink title font if it doesn't fit with battery + 5px gap
            max_title_w = icon_x - tx - 5
            while fs > 10 and self.pager.ttf_width(title, self.font_viking, fs) > max_title_w:
                fs -= 1

        tw = self.pager.ttf_width(title, self.font_viking, fs)
        th = self.pager.ttf_height(self.font_viking, fs)
        # Left-align title, vertically centered + theme offset
        ty = L["y"] + (L["h"] - 1 - th) // 2
        ty += getattr(self.shared_data, 'theme_title_y_offset', 0)
        self.pager.draw_ttf(tx, ty, title, self.TITLE_COLOR, self.font_viking, fs)

        # Battery indicator — right-aligned within header area
        if bat is not None:
            icon_y = L["y"] + (L["h"] - 1 - icon_h) // 2

            # Draw battery icon
            self.draw_icon_scaled(icon_x, icon_y, icon_w, icon_h, 'battery')

            # Draw level text centered inside the icon (no % sign)
            bat_text = f"{bat}"
            if self.shared_data.battery_charging:
                bat_text += "+"
            bat_fs = 18
            btw = self.pager.ttf_width(bat_text, self.font_arial, bat_fs)
            bth = self.pager.ttf_height(self.font_arial, bat_fs)
            bt_x = icon_x + (icon_w - btw) // 2
            bt_y = icon_y + (icon_h - bth) // 2
            bat_color = self.ACCENT_COLOR if self.shared_data.battery_charging else self.TEXT_COLOR
            self.pager.draw_ttf(bt_x, bt_y, bat_text, bat_color, self.font_arial, bat_fs)

    def draw_stats_grid(self):
        """Stats grid with icons and numbers (3x2 grid)."""
        L = self.layout["stats_grid"]

        self.pager.fill_rect(L["x"], L["y"], L["w"], L["h"], self.BG_COLOR)
        if self.orientation == "landscape":
            # Skip top/bottom/left border lines — frise serves as left edge
            self.pager.vline(L["x"] + L["w"] - 1, L["y"], L["h"], self.TEXT_COLOR)
        else:
            # Top and bottom lines only — no left/right borders at screen edge
            self.pager.hline(L["x"], L["y"], L["w"], self.TEXT_COLOR)
            self.pager.hline(L["x"], L["y"] + L["h"] - 1, L["w"], self.TEXT_COLOR)

        cols = L["cols"]
        rows = L["rows"]
        col_w = L["w"] // cols
        row_h = L["h"] // rows
        icon_size = L["icon_size"]
        font_size = L["font_size"]

        stats = [
            ('target', self.shared_data.targetnbr),
            ('port', self.shared_data.portnbr),
            ('vuln', self.shared_data.vulnnbr),
            ('cred', self.shared_data.crednbr),
            ('zombie', self.shared_data.zombiesnbr),
            ('data', self.shared_data.datanbr),
        ]

        for idx, (icon_name, value) in enumerate(stats):
            col = idx % cols
            row = idx // cols
            cx = L["x"] + col * col_w
            cy = L["y"] + row * row_h

            icon_x = cx + 4
            # Nudge credentials icon left 2px in landscape
            if icon_name == 'cred' and self.orientation == "landscape":
                icon_x -= 2
            icon_y = cy + (row_h - icon_size) // 2
            self.draw_icon_scaled(icon_x, icon_y, icon_size, icon_size, icon_name)

            text_x = icon_x + icon_size + 4
            text_y = cy + (row_h - font_size) // 2
            self.pager.draw_ttf(text_x, text_y, str(value), self.TEXT_COLOR, self.font_arial, font_size)

        # Grid lines
        for i in range(1, cols):
            self.pager.vline(L["x"] + i * col_w, L["y"], L["h"], self.TEXT_COLOR)
        if self.orientation == "landscape":
            # Match horizontal lines to status_area extent
            S = self.layout["status_area"]
            for i in range(1, rows):
                self.pager.hline(S["x"], L["y"] + i * row_h, S["w"], self.TEXT_COLOR)
        else:
            for i in range(1, rows):
                self.pager.hline(L["x"], L["y"] + i * row_h, L["w"], self.TEXT_COLOR)

    def draw_status_area(self):
        """Status: action icon + status text."""
        L = self.layout["status_area"]

        self.pager.fill_rect(L["x"], L["y"], L["w"], L["h"], self.BG_COLOR)
        if self.orientation == "landscape":
            # Skip left border — frise serves as left edge
            self.pager.vline(L["x"] + L["w"] - 1, L["y"], L["h"], self.TEXT_COLOR)
            self.pager.hline(L["x"], L["y"], L["w"], self.TEXT_COLOR)
            self.pager.hline(L["x"], L["y"] + L["h"] - 1, L["w"], self.TEXT_COLOR)
        else:
            # Top and bottom lines only — no left/right borders at screen edge
            self.pager.hline(L["x"], L["y"], L["w"], self.TEXT_COLOR)
            self.pager.hline(L["x"], L["y"] + L["h"] - 1, L["w"], self.TEXT_COLOR)

        icon_size = L["icon_size"]
        icon_x = L["x"] + 6
        icon_y = L["y"] + (L["h"] - icon_size) // 2

        if self.shared_data.bjornstatusimage_path and os.path.exists(self.shared_data.bjornstatusimage_path):
            try:
                self.pager.draw_image_file_scaled(icon_x, icon_y, icon_size, icon_size,
                                                   self.shared_data.bjornstatusimage_path)
            except:
                pass

        text_x = icon_x + icon_size + 8
        max_text_w = L["x"] + L["w"] - text_x - 4
        main_font = L["main_font_size"]
        sub_font = L["sub_font_size"]

        status_text = self.shared_data.bjornstatustext
        font_size = main_font
        while font_size > 10 and self.pager.ttf_width(status_text, self.font_arial, font_size) > max_text_w:
            font_size -= 1
        self.pager.draw_ttf(text_x, L["y"] + 4, status_text, self.TEXT_COLOR, self.font_arial, font_size)

        status_text2 = self.shared_data.bjornstatustext2
        font_size2 = sub_font
        while font_size2 > 8 and self.pager.ttf_width(status_text2, self.font_arial, font_size2) > max_text_w:
            font_size2 -= 1
        self.pager.draw_ttf(text_x, L["y"] + 4 + main_font + 2, status_text2, self.ACCENT_COLOR, self.font_arial, font_size2)

    def draw_dialogue_zone(self):
        """Viking speech bubble."""
        L = self.layout["dialogue"]

        self.pager.fill_rect(L["x"], L["y"], L["w"], L["h"], self.BG_COLOR)
        if self.orientation == "landscape":
            # Skip bottom/left border — frise serves as left edge
            self.pager.vline(L["x"] + L["w"] - 1, L["y"], L["h"], self.TEXT_COLOR)
            self.pager.hline(L["x"], L["y"], L["w"], self.TEXT_COLOR)
        else:
            # Top and bottom lines only — no left/right borders at screen edge
            self.pager.hline(L["x"], L["y"], L["w"], self.TEXT_COLOR)
            self.pager.hline(L["x"], L["y"] + L["h"] - 1, L["w"], self.TEXT_COLOR)

        font_size = L["font_size"]
        line_height = L["line_height"]
        margin = L["margin"]
        max_lines = L["max_lines"]
        text_x = L["x"] + margin
        max_w = L["w"] - margin * 2
        text_y = L["y"] + margin

        if hasattr(self.shared_data, 'bjornsay') and self.shared_data.bjornsay:
            clean_text = self.sanitize_text(self.shared_data.bjornsay)
            lines = self._wrap_text_pixel(clean_text, self.font_arial, font_size, max_w)
            for i, line in enumerate(lines[:max_lines]):
                self.pager.draw_ttf(text_x, text_y + i * line_height, line, self.TEXT_COLOR, self.font_arial, font_size)

    def draw_frise(self):
        """Celtic knot ribbon (hidden in landscape where h=0)."""
        L = self.layout["frise"]
        if L["h"] <= 0:
            return

        frise_path = self.shared_data.static_images.get('frise')
        if frise_path and os.path.exists(frise_path):
            try:
                if self.orientation == "landscape":
                    self.pager.draw_image_file_scaled_rotated(L["x"], L["y"], L["w"], L["h"], frise_path, 90)
                else:
                    self.pager.draw_image_file_scaled(L["x"], L["y"], L["w"], L["h"], frise_path)
            except:
                pass

    def draw_character_and_corner_stats(self):
        """Viking character with stats in corners."""
        C = self.layout["character"]
        CS = self.layout["corner_stats"]

        # Draw character
        if self.main_image_path and os.path.exists(self.main_image_path):
            try:
                self.pager.draw_image_file_scaled(C["x"], C["y"], C["w"], C["h"], self.main_image_path)
            except Exception as e:
                logger.debug(f"Could not draw character: {e}")
                self.pager.draw_ttf(C["x"] + 20, C["y"] + 30, "?", self.TEXT_COLOR, self.font_viking, 36)

        icon_size = CS["icon_size"]
        num_font = CS["font_size"]
        area_x = CS["area_x"]
        area_w = CS["area_w"]

        # Corner y positions: use explicit values if set, otherwise compute from character rect
        top_y = CS.get("top_y", C["y"] + 10)
        bottom_y = CS.get("bottom_y", C["y"] + C["h"] - icon_size - num_font + 26)

        # TOP-LEFT: Coins
        x = area_x + 4
        self.draw_icon_scaled(x, top_y, icon_size, icon_size, 'gold')
        val = str(self.shared_data.coinnbr)
        tw = self.pager.ttf_width(val, self.font_arial, num_font)
        self.pager.draw_ttf(x + (icon_size - tw) // 2, top_y + icon_size + 2, val, self.TEXT_COLOR, self.font_arial, num_font)

        # BOTTOM-LEFT: Level
        x = area_x + 4
        self.draw_icon_scaled(x, bottom_y, icon_size, icon_size, 'level')
        val = str(self.shared_data.levelnbr)
        tw = self.pager.ttf_width(val, self.font_arial, num_font)
        self.pager.draw_ttf(x + (icon_size - tw) // 2, bottom_y + icon_size + 2, val, self.TEXT_COLOR, self.font_arial, num_font)

        # TOP-RIGHT: Network KB
        x = area_x + area_w - icon_size - 4
        self.draw_icon_scaled(x, top_y, icon_size, icon_size, 'networkkb')
        val = str(self.shared_data.networkkbnbr)
        tw = self.pager.ttf_width(val, self.font_arial, num_font)
        self.pager.draw_ttf(x + (icon_size - tw) // 2, top_y + icon_size + 2, val, self.TEXT_COLOR, self.font_arial, num_font)

        # BOTTOM-RIGHT: Attacks
        x = area_x + area_w - icon_size - 4
        self.draw_icon_scaled(x, bottom_y, icon_size, icon_size, 'attacks')
        val = str(self.shared_data.attacksnbr)
        tw = self.pager.ttf_width(val, self.font_arial, num_font)
        self.pager.draw_ttf(x + (icon_size - tw) // 2, bottom_y + icon_size + 2, val, self.TEXT_COLOR, self.font_arial, num_font)

    # ------------------------------------------------------------------
    # Render + main loop
    # ------------------------------------------------------------------

    def render_frame(self):
        """Render complete frame."""
        if self.dialog_showing:
            return

        self.pager.clear(self.BG_COLOR)

        self.draw_header()
        self.draw_stats_grid()
        self.draw_status_area()
        self.draw_dialogue_zone()
        self.draw_frise()
        self.draw_character_and_corner_stats()

        if not self.dialog_showing:
            self.pager.flip()

    def run(self):
        """Main display loop."""
        logger.info("Starting display main loop...")

        while not self.shared_data.display_should_exit:
            try:
                if self.dialog_showing:
                    time.sleep(0.1)
                    continue

                self.check_dim_timeout()
                self.display_comment(self.shared_data.bjornorch_status)
                self.shared_data.update_bjornstatus()
                self.update_leds(self.shared_data.bjornorch_status)
                self.render_frame()
                time.sleep(0.05)
            except Exception as e:
                logger.error(f"Error in display loop: {e}")
                time.sleep(0.1)

        logger.info("Display loop exiting...")
        self.cleanup()

    def cleanup(self):
        if self._cleaned_up:
            return
        self._cleaned_up = True
        try:
            logger.info("Cleaning up display...")
            self.pager.led_all_off()
            self.pager.clear(self.BLACK)
            self.pager.flip()
            self.pager.cleanup()
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


def handle_exit_display(signum, frame, display_instance):
    logger.info("Exit signal received...")
    shared_data.display_should_exit = True
    shared_data.should_exit = True
    if display_instance:
        display_instance.cleanup()
    sys.exit(0)


display_instance = None


if __name__ == "__main__":
    try:
        logger.info("Starting Bjorn display...")
        display_instance = Display(shared_data)

        signal.signal(signal.SIGINT, lambda s, f: handle_exit_display(s, f, display_instance))
        signal.signal(signal.SIGTERM, lambda s, f: handle_exit_display(s, f, display_instance))

        display_instance.run()

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if display_instance:
            display_instance.cleanup()
        sys.exit(1)
