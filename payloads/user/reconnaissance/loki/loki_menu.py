"""
Graphical startup menu for Loki
Uses libpagerctl.so for fast native rendering in landscape mode (270, 480x222)
"""

import os
import sys
import subprocess
import time
import json

PAYLOAD_DIR = os.path.dirname(os.path.abspath(__file__))

# System font paths (theme title font overrides Viking in _apply_theme)
FONTS_DIR = os.path.join(PAYLOAD_DIR, 'resources', 'fonts')
FONT_VIKING = os.path.join(PAYLOAD_DIR, 'themes', 'loki', 'fonts', 'title.TTF')
FONT_DEJAVU = os.path.join(FONTS_DIR, 'DejaVuSansMono.ttf')

# TTF font sizes
TTF_SMALL = 14.0
TTF_MEDIUM = 18.0
TTF_LARGE = 24.0

# Loot directory paths
LOOT_DIR = "/mmc/root/loot/loki"
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


class LokiMenu:
    """Graphical startup menu for Loki on the Pager LCD."""

    def __init__(self, interfaces):
        self.interfaces = interfaces
        self.scan_prefix = 24
        self.menu_title = "Loki"
        self.title_font = FONT_VIKING
        self.config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'shared_config.json')
        self.themes_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'themes')
        self.available_themes = self._discover_themes()
        self.active_theme = 'bjorn'
        self.display_landscape = True  # Default: landscape (rotation=270)
        self.web_ui = True  # Default: web UI enabled
        try:
            with open(self.config_path, 'r') as f:
                cfg = json.load(f)
            self.scan_prefix = cfg.get('scan_network_prefix', 24)
            self.active_theme = cfg.get('theme', 'bjorn')
            self.display_landscape = cfg.get('screen_rotation', 270) == 270
            self.web_ui = cfg.get('web_ui', True)
        except Exception:
            pass
        self._apply_theme(self.active_theme)
        self.gfx = Pager()
        self.gfx.init()
        self.gfx.set_rotation(270)  # Landscape 480x222

    def cleanup(self):
        if hasattr(self, 'gfx'):
            self.gfx.cleanup()

    def _discover_themes(self):
        """Scan themes/ directory for valid theme folders (must contain theme.json)."""
        themes = []
        self.theme_display_names = {}
        if os.path.isdir(self.themes_dir):
            for name in sorted(os.listdir(self.themes_dir)):
                theme_json = os.path.join(self.themes_dir, name, 'theme.json')
                if os.path.isfile(theme_json):
                    themes.append(name)
                    try:
                        with open(theme_json, 'r') as f:
                            td = json.load(f)
                        self.theme_display_names[name] = td.get('theme_name', name)
                    except Exception:
                        self.theme_display_names[name] = name
        if not themes:
            themes = ['bjorn']
        return themes

    def _apply_theme(self, theme_name):
        """Load menu_title, title_font, mood labels, colors, and bg images from the given theme."""
        self.active_theme = theme_name
        self.menu_title = "Loki"
        self.title_font = FONT_VIKING
        self.menu_font = FONT_DEJAVU
        self.theme_moods = {}

        # Default menu colors
        self.menu_bg_color = Pager.BLACK  # used for dialogs/submenus without skin images
        self.menu_title_color = TITLE_COLOR
        self.menu_selected_color = SELECTED_COLOR
        self.menu_unselected_color = UNSELECTED_COLOR
        self.menu_on_color = ON_COLOR
        self.menu_off_color = OFF_COLOR
        self.menu_dim_color = DIM_COLOR
        self.menu_warning_color = WARNING_COLOR
        self.menu_submenu_color = SUBMENU_COLOR

        theme_dir = os.path.join(self.themes_dir, theme_name)
        theme_json = os.path.join(theme_dir, 'theme.json')
        if os.path.isfile(theme_json):
            try:
                with open(theme_json, 'r') as f:
                    theme_data = json.load(f)
                self.menu_title = theme_data.get('theme_name', self.menu_title)
                self.theme_moods = theme_data.get('moods', {})

                # Themeable menu colors
                mc = theme_data.get('menu_colors', {})
                if mc:
                    def _c(key, default):
                        v = mc.get(key)
                        return Pager.rgb(v[0], v[1], v[2]) if v else default
                    self.menu_bg_color = _c('bg', self.menu_bg_color)
                    self.menu_title_color = _c('title', self.menu_title_color)
                    self.menu_selected_color = _c('selected', self.menu_selected_color)
                    self.menu_unselected_color = _c('unselected', self.menu_unselected_color)
                    self.menu_on_color = _c('on', self.menu_on_color)
                    self.menu_off_color = _c('off', self.menu_off_color)
                    self.menu_dim_color = _c('dim', self.menu_dim_color)
                    self.menu_warning_color = _c('warning', self.menu_warning_color)
                    self.menu_submenu_color = _c('submenu', self.menu_submenu_color)
            except Exception:
                pass
        theme_font = os.path.join(theme_dir, 'fonts', 'title.TTF')
        if os.path.isfile(theme_font):
            self.title_font = theme_font

        # Menu body font (optional) — check menu.ttf / menu.TTF / menu.otf
        for fname in ('menu.ttf', 'menu.TTF', 'menu.otf'):
            mf = os.path.join(theme_dir, 'fonts', fname)
            if os.path.isfile(mf):
                self.menu_font = mf
                break

        # Menu background images (optional)
        images_dir = os.path.join(theme_dir, 'images')
        self.menu_bg = None
        self.settings_bg = None
        for name, attr in [('menu_bg', 'menu_bg'), ('settings_bg', 'settings_bg')]:
            for ext in ('.png', '.bmp'):
                path = os.path.join(images_dir, name + ext)
                if os.path.isfile(path):
                    setattr(self, attr, path)
                    break

    def _save_theme(self, theme_name):
        """Save the selected theme to shared_config.json."""
        try:
            with open(self.config_path, 'r') as f:
                cfg = json.load(f)
            cfg['theme'] = theme_name
            with open(self.config_path, 'w') as f:
                json.dump(cfg, f, indent=4)
        except Exception:
            pass

    def _save_rotation(self, landscape):
        """Save the selected screen rotation to shared_config.json."""
        try:
            with open(self.config_path, 'r') as f:
                cfg = json.load(f)
            cfg['screen_rotation'] = 270 if landscape else 0
            with open(self.config_path, 'w') as f:
                json.dump(cfg, f, indent=4)
        except Exception:
            pass

    def _save_web_ui(self, enabled):
        """Save the web_ui setting to shared_config.json."""
        self.web_ui = enabled
        try:
            with open(self.config_path, 'r') as f:
                cfg = json.load(f)
            cfg['web_ui'] = enabled
            with open(self.config_path, 'w') as f:
                json.dump(cfg, f, indent=4)
        except Exception:
            pass

    MOOD_PRESETS = [
        ('target', {'brute_force_running': True,  'scan_vuln_running': True,  'file_steal_running': True,  'attack_order': 'per_host'}),
        ('swarm',  {'brute_force_running': True,  'scan_vuln_running': True,  'file_steal_running': True,  'attack_order': 'spread'}),
        ('recon',  {'brute_force_running': False, 'scan_vuln_running': False, 'file_steal_running': False, 'attack_order': 'spread'}),
    ]

    _MOOD_DEFAULTS = {'target': 'Target', 'swarm': 'Swarm', 'recon': 'Recon'}
    _ORDER_LABELS = ['Spread', 'Per Host', 'Per Phase']
    _ORDER_VALUES = ['spread', 'per_host', 'per_phase']

    def _mood_label(self, preset_key):
        """Get mood display label from theme, falling back to defaults."""
        return self.theme_moods.get(preset_key, self._MOOD_DEFAULTS[preset_key])

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

    def _draw_main_menu(self, selected, iface_idx, theme_idx):
        """Draw the main menu screen."""
        if self.menu_bg:
            ret = self.gfx.draw_image_file_scaled(0, 0, 480, 222, self.menu_bg)
            if ret != 0:
                self.gfx.clear(self.menu_bg_color)
        else:
            self.gfx.clear(self.menu_bg_color)

        # Title is baked into menu background image

        # Menu items
        y = 55
        items = self._get_menu_items(iface_idx, theme_idx)

        for i, item in enumerate(items):
            is_selected = (i == selected)

            if item.get('toggle'):
                # Toggle item: label + value
                label = item['label']
                value = item['value']
                value_color = item['value_color']
                label_color = self.menu_selected_color if is_selected else self.menu_unselected_color

                # Calculate fixed positions using max value width for alignment
                max_value = item.get('max_value', value)
                label_width = self.gfx.ttf_width(label, self.menu_font, TTF_MEDIUM)
                max_value_width = self.gfx.ttf_width(max_value, self.menu_font, TTF_MEDIUM)
                total_width = label_width + 8 + max_value_width
                start_x = (480 - total_width) // 2
                self.gfx.draw_ttf(start_x, y, label, label_color, self.menu_font, TTF_MEDIUM)
                self.gfx.draw_ttf(start_x + label_width + 8, y, value, value_color, self.menu_font, TTF_MEDIUM)
            else:
                # Simple menu item
                color = self.menu_selected_color if is_selected else self.menu_unselected_color
                self.gfx.draw_ttf_centered(y, item['label'], color, self.menu_font, TTF_MEDIUM)

            y += 22

        self.gfx.flip()

    def _get_menu_items(self, iface_idx, theme_idx):
        """Build the list of menu items for drawing."""
        items = [{'label': 'Start'}]

        # Network selector — show IP/prefix only, stable label position
        if self.interfaces:
            iface = self.interfaces[iface_idx]
            net_text = f"{iface['ip']}/{self.scan_prefix}"
            max_net = max((f"{i['ip']}/{self.scan_prefix}" for i in self.interfaces), key=len)
        else:
            net_text = "none"
            max_net = "none"

        items.append({
            'toggle': True,
            'label': 'Network:',
            'value': net_text,
            'value_color': self.menu_unselected_color,
            'max_value': max_net,
        })

        # Theme selector
        theme_key = self.available_themes[theme_idx] if self.available_themes else 'bjorn'
        theme_display = self.theme_display_names.get(theme_key, theme_key)
        max_theme_display = max(self.theme_display_names.values(), key=len) if self.theme_display_names else theme_display
        items.append({
            'toggle': True,
            'label': 'Theme:',
            'value': theme_display,
            'value_color': self.menu_title_color,
            'max_value': max_theme_display,
        })

        # Display orientation
        items.append({
            'toggle': True,
            'label': 'Display:',
            'value': 'Landscape' if self.display_landscape else 'Portrait',
            'value_color': self.menu_title_color,
            'max_value': 'Landscape',
        })

        items.append({'label': 'Clear Data'})
        items.append({'label': 'Settings'})
        items.append({'label': 'Exit'})
        return items

    def show_main_menu(self):
        """Show the main menu. Returns config dict or None to exit."""
        selected = 0
        iface_idx = 0
        # Find the index of the active theme
        theme_idx = 0
        if self.active_theme in self.available_themes:
            theme_idx = self.available_themes.index(self.active_theme)
        num_options = 7  # Start, Network, Theme, Display, Clear Data, Settings, Exit

        def redraw():
            self._draw_main_menu(selected, iface_idx, theme_idx)

        redraw()

        while True:
            btn = self._wait_button()

            if btn == 'UP':
                selected = (selected - 1) % num_options
                redraw()
            elif btn == 'DOWN':
                selected = (selected + 1) % num_options
                redraw()
            elif btn in ['LEFT', 'RIGHT']:
                if selected == 1 and self.interfaces:
                    # Cycle network interface
                    if btn == 'RIGHT':
                        iface_idx = (iface_idx + 1) % len(self.interfaces)
                    else:
                        iface_idx = (iface_idx - 1) % len(self.interfaces)
                    redraw()
                elif selected == 2 and self.available_themes:
                    # Cycle theme
                    if btn == 'RIGHT':
                        theme_idx = (theme_idx + 1) % len(self.available_themes)
                    else:
                        theme_idx = (theme_idx - 1) % len(self.available_themes)
                    self._apply_theme(self.available_themes[theme_idx])
                    self._save_theme(self.available_themes[theme_idx])
                    redraw()
                elif selected == 3:
                    # Toggle display orientation
                    self.display_landscape = not self.display_landscape
                    self._save_rotation(self.display_landscape)
                    redraw()
            elif btn == 'SELECT':
                if selected == 0:
                    # Start Bjorn
                    if not self.interfaces:
                        self._show_message("No network!", WARNING_COLOR, "Connect to a network first", DIM_COLOR)
                        self._wait_button()
                        redraw()
                        continue
                    iface = self.interfaces[iface_idx]
                    return {
                        'interface': iface['name'],
                        'ip': iface['ip'],
                        'web_ui': self.web_ui,
                    }
                elif selected == 1 and self.interfaces:
                    # Cycle network forward on select
                    iface_idx = (iface_idx + 1) % len(self.interfaces)
                    redraw()
                elif selected == 2 and self.available_themes:
                    # Cycle theme forward on select
                    theme_idx = (theme_idx + 1) % len(self.available_themes)
                    self._apply_theme(self.available_themes[theme_idx])
                    self._save_theme(self.available_themes[theme_idx])
                    redraw()
                elif selected == 3:
                    # Toggle display orientation on select
                    self.display_landscape = not self.display_landscape
                    self._save_rotation(self.display_landscape)
                    redraw()
                elif selected == 4:
                    # Clear Data submenu
                    self._show_clear_data_menu()
                    redraw()
                elif selected == 5:
                    # Settings submenu
                    self._show_settings_menu()
                    redraw()
                elif selected == 6:
                    # Exit
                    return None

    def _show_message(self, text, color, subtext=None, subcolor=None):
        """Show a centered message on screen."""
        self.gfx.clear(self.menu_bg_color)
        self.gfx.draw_ttf_centered(80, text, color, self.menu_font, TTF_LARGE)
        if subtext and subcolor:
            self.gfx.draw_ttf_centered(115, subtext, subcolor, self.menu_font, TTF_SMALL)
        self.gfx.flip()

    def _show_settings_menu(self):
        """Show the Settings submenu with attack presets, toggles, and orientation."""
        # Read current config
        try:
            with open(self.config_path, 'r') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}

        # Current values
        web_ui_idx = 1 if self.web_ui else 0
        manual_val = cfg.get('manual_mode', False)
        bf_val = cfg.get('brute_force_running', True)
        vs_val = cfg.get('scan_vuln_running', True)
        fs_val = cfg.get('file_steal_running', True)
        order_val = cfg.get('attack_order', 'spread')
        order_idx = self._ORDER_VALUES.index(order_val) if order_val in self._ORDER_VALUES else 0

        # Mood labels from active theme
        mood_labels = [self._mood_label(k) for k, _ in self.MOOD_PRESETS]
        mood_idx = 0

        items = [
            ('web_ui',       'Web UI',       ['OFF', 'ON'],                     web_ui_idx),
            ('manual_mode',  'Manual Mode',  ['OFF', 'ON'],                     int(manual_val)),
            ('mood',         'Mood',         mood_labels,                       mood_idx),
            ('brute_force',  'Brute Force',  ['OFF', 'ON'],                     int(bf_val)),
            ('vuln_scan',    'Vuln Scan',    ['OFF', 'ON'],                     int(vs_val)),
            ('file_steal',   'File Steal',   ['OFF', 'ON'],                     int(fs_val)),
            ('attack_order', 'Attack Order', self._ORDER_LABELS,                order_idx),
        ]

        selected = 0
        num_items = len(items)
        _ATTACK_KEYS = {'mood', 'brute_force', 'vuln_scan', 'file_steal', 'attack_order'}

        def is_manual():
            for key, _l, _c, idx in items:
                if key == 'manual_mode':
                    return bool(idx)
            return False

        def apply_mood(m_idx):
            _key, preset = self.MOOD_PRESETS[m_idx]
            for i, (key, label, choices, _idx) in enumerate(items):
                if key == 'mood':
                    items[i] = (key, label, choices, m_idx)
                elif key == 'brute_force':
                    items[i] = (key, label, choices, int(preset['brute_force_running']))
                elif key == 'vuln_scan':
                    items[i] = (key, label, choices, int(preset['scan_vuln_running']))
                elif key == 'file_steal':
                    items[i] = (key, label, choices, int(preset['file_steal_running']))
                elif key == 'attack_order':
                    ov = preset['attack_order']
                    items[i] = (key, label, choices, self._ORDER_VALUES.index(ov))

        def save_settings():
            try:
                with open(self.config_path, 'r') as f:
                    c = json.load(f)
            except Exception:
                c = {}
            for key, _label, choices, idx in items:
                if key == 'web_ui':
                    self.web_ui = bool(idx)
                    c['web_ui'] = self.web_ui
                elif key == 'manual_mode':
                    c['manual_mode'] = bool(idx)
                elif key == 'mood':
                    continue
                elif key == 'brute_force':
                    c['brute_force_running'] = bool(idx)
                elif key == 'vuln_scan':
                    c['scan_vuln_running'] = bool(idx)
                elif key == 'file_steal':
                    c['file_steal_running'] = bool(idx)
                elif key == 'attack_order':
                    c['attack_order'] = self._ORDER_VALUES[idx]
            try:
                with open(self.config_path, 'w') as f:
                    json.dump(c, f, indent=4)
            except Exception:
                pass

        def draw_menu():
            if self.settings_bg:
                self.gfx.draw_image_file_scaled(0, 0, 480, 222, self.settings_bg)
            else:
                self.gfx.clear(self.menu_bg_color)
            # Settings title is baked into settings background image

            manual = is_manual()
            y = 42
            for i, (key, label, choices, idx) in enumerate(items):
                is_sel = (i == selected)
                disabled = manual and key in _ATTACK_KEYS

                if disabled:
                    value = 'N/A'
                    label_color = self.menu_dim_color
                    val_color = self.menu_dim_color
                else:
                    value = choices[idx]
                    label_color = self.menu_selected_color if is_sel else self.menu_unselected_color
                    if key in ('web_ui', 'manual_mode', 'brute_force', 'vuln_scan', 'file_steal'):
                        val_color = self.menu_on_color if idx else self.menu_off_color
                    elif key == 'mood':
                        val_color = self.menu_title_color
                    else:
                        val_color = self.menu_unselected_color

                # Draw label: value with stable alignment
                label_text = f"{label}:"
                label_width = self.gfx.ttf_width(label_text, self.menu_font, TTF_MEDIUM)
                # Use actual choices for width calc even when showing N/A
                max_val_w = max(self.gfx.ttf_width(c, self.menu_font, TTF_MEDIUM) for c in choices)
                na_w = self.gfx.ttf_width('N/A', self.menu_font, TTF_MEDIUM)
                if na_w > max_val_w:
                    max_val_w = na_w
                total_width = label_width + 8 + max_val_w
                start_x = (480 - total_width) // 2

                self.gfx.draw_ttf(start_x, y, label_text, label_color, self.menu_font, TTF_MEDIUM)

                # Right-align value within max_val_w area
                val_w = self.gfx.ttf_width(value, self.menu_font, TTF_MEDIUM)
                val_x = start_x + label_width + 8 + (max_val_w - val_w)
                self.gfx.draw_ttf(val_x, y, value, val_color, self.menu_font, TTF_MEDIUM)

                y += 24

            self.gfx.flip()

        draw_menu()

        while True:
            btn = self._wait_button()

            if btn == 'UP':
                selected = (selected - 1) % num_items
                draw_menu()
            elif btn == 'DOWN':
                selected = (selected + 1) % num_items
                draw_menu()
            elif btn in ['LEFT', 'RIGHT']:
                key, label, choices, idx = items[selected]
                if is_manual() and key in _ATTACK_KEYS:
                    continue
                if btn == 'RIGHT':
                    new_idx = (idx + 1) % len(choices)
                else:
                    new_idx = (idx - 1) % len(choices)
                items[selected] = (key, label, choices, new_idx)
                if key == 'mood':
                    apply_mood(new_idx)
                draw_menu()
            elif btn == 'SELECT':
                key, label, choices, idx = items[selected]
                if is_manual() and key in _ATTACK_KEYS:
                    continue
                new_idx = (idx + 1) % len(choices)
                items[selected] = (key, label, choices, new_idx)
                if key == 'mood':
                    apply_mood(new_idx)
                draw_menu()
            elif btn == 'BACK':
                save_settings()
                return

    def _show_clear_data_menu(self):
        """Show the Clear Data submenu."""
        selected = 0
        options = ['Clear Logs', 'Clear Credentials', 'Clear Stolen Data', 'Clear All', 'Back']

        while True:
            self.gfx.clear(self.menu_bg_color)
            self.gfx.draw_ttf_centered(12, "CLEAR DATA", self.menu_submenu_color, self.menu_font, TTF_LARGE)

            y = 55
            for i, opt in enumerate(options):
                color = self.menu_selected_color if i == selected else self.menu_unselected_color
                self.gfx.draw_ttf_centered(y, opt, color, self.menu_font, TTF_MEDIUM)
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
            self.gfx.clear(self.menu_bg_color)
            self.gfx.draw_ttf_centered(60, prompt, self.menu_warning_color, self.menu_font, TTF_LARGE)

            center = 480 // 2
            yes_color = self.menu_selected_color if selected == 0 else self.menu_unselected_color
            no_color = self.menu_selected_color if selected == 1 else self.menu_unselected_color
            self.gfx.draw_ttf(center - 85, 115, "YES", yes_color, self.menu_font, TTF_MEDIUM)
            self.gfx.draw_ttf(center + 45, 115, "NO", no_color, self.menu_font, TTF_MEDIUM)
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
        """Clear all Loki data."""
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
    """Main entry point: menu loop -> launch Loki -> repeat."""
    menu = None
    try:
        while True:
            interfaces = detect_interfaces()

            # Give pagerctl time to release after Loki's os._exit()
            time.sleep(0.3)

            try:
                menu = LokiMenu(interfaces)
            except Exception as e:
                # Pagerctl init can fail after unclean exit - retry once
                time.sleep(1)
                try:
                    menu = LokiMenu(interfaces)
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
            menu._show_message("Starting Loki...", TITLE_COLOR, result['interface'] + " " + result['ip'], DIM_COLOR)
            menu.cleanup()
            menu = None

            # Launch Loki as subprocess
            env = os.environ.copy()
            env['BJORN_INTERFACE'] = result['interface']
            env['BJORN_IP'] = result['ip']
            env['BJORN_WEB_UI'] = 'on' if result['web_ui'] else 'off'

            proc = subprocess.run(
                ['python3', 'Loki.py'],
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

            # Exit Loki (code 0) — break out of loop
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
