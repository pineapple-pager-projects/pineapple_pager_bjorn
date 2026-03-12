/* ========================================
   Bjorn Cyberviking - SPA Core
   ======================================== */
'use strict';

const App = {
    activeTab: null,
    tabs: {},
    pollTimers: {},
    theme: null,

    init() {
        // Migrate old tab names in localStorage
        var saved = localStorage.getItem('bjorn_active_tab');
        if (saved === 'network') localStorage.setItem('bjorn_active_tab', 'hosts');
        if (saved === 'bjorn') localStorage.setItem('bjorn_active_tab', 'display');

        // Bind nav clicks
        document.querySelectorAll('.nav-item').forEach(el => {
            el.addEventListener('click', e => {
                e.preventDefault();
                this.switchTab(el.dataset.tab);
            });
        });

        // Hash change handling (support old hash names too)
        window.addEventListener('hashchange', () => {
            var tab = this.resolveTabName(location.hash.slice(1));
            if (tab && this.tabs[tab]) this.switchTab(tab);
        });

        // Initialize all registered tabs
        Object.keys(this.tabs).forEach(id => {
            if (this.tabs[id].init) this.tabs[id].init();
        });

        // Load theme before first tab switch
        this.loadTheme();

        // Restore last tab or use hash or default to dashboard
        var hash = this.resolveTabName(location.hash.slice(1));
        saved = localStorage.getItem('bjorn_active_tab');
        var initial = (hash && this.tabs[hash]) ? hash
                      : (saved && this.tabs[saved]) ? saved
                      : 'dashboard';
        this.switchTab(initial);
    },

    resolveTabName(name) {
        // Map old tab names to new ones
        if (name === 'network') return 'hosts';
        if (name === 'bjorn') return 'display';
        return name;
    },

    registerTab(id, module) {
        this.tabs[id] = module;
    },

    switchTab(id) {
        if (!this.tabs[id]) return;
        if (this.activeTab === id) return;

        // Deactivate current
        if (this.activeTab && this.tabs[this.activeTab]) {
            const prev = this.tabs[this.activeTab];
            if (prev.deactivate) prev.deactivate();
            this.stopPolling(this.activeTab);
            const prevPanel = document.getElementById('tab-' + this.activeTab);
            if (prevPanel) prevPanel.classList.remove('active');
        }

        // Update nav
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.toggle('active', el.dataset.tab === id);
        });

        // Activate new
        this.activeTab = id;
        const panel = document.getElementById('tab-' + id);
        if (panel) panel.classList.add('active');

        const tab = this.tabs[id];
        if (tab.activate) tab.activate();

        // Update URL hash and save preference
        if (location.hash !== '#' + id) {
            history.replaceState(null, '', '#' + id);
        }
        localStorage.setItem('bjorn_active_tab', id);
    },

    startPolling(tabId, fn, interval) {
        this.stopPolling(tabId);
        fn(); // Immediate first call
        this.pollTimers[tabId] = setInterval(() => {
            // Only poll if this tab is still active
            if (this.activeTab === tabId) fn();
        }, interval);
    },

    stopPolling(tabId) {
        if (this.pollTimers[tabId]) {
            clearInterval(this.pollTimers[tabId]);
            delete this.pollTimers[tabId];
        }
    },

    async api(url, opts) {
        try {
            const resp = await fetch(url, opts || {});
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            const ct = resp.headers.get('content-type') || '';
            if (ct.includes('json')) return resp.json();
            return resp.text();
        } catch (e) {
            console.error('API error:', url, e);
            throw e;
        }
    },

    async post(url, data) {
        return this.api(url, {
            method: 'POST',
            headers: data ? { 'Content-Type': 'application/json' } : {},
            body: data ? JSON.stringify(data) : undefined
        });
    },

    toast(msg, type) {
        type = type || 'info';
        const container = document.getElementById('toast-container');
        const el = document.createElement('div');
        el.className = 'toast toast-' + type;
        el.textContent = msg;
        container.appendChild(el);
        setTimeout(() => {
            el.classList.add('removing');
            setTimeout(() => el.remove(), 300);
        }, 3000);
    },

    confirm(msg) {
        return new Promise(resolve => {
            const modal = document.getElementById('confirm-modal');
            const msgEl = document.getElementById('confirm-message');
            const yesBtn = document.getElementById('confirm-yes');
            const noBtn = document.getElementById('confirm-no');
            msgEl.textContent = msg;
            modal.classList.remove('hidden');

            const cleanup = result => {
                modal.classList.add('hidden');
                yesBtn.removeEventListener('click', onYes);
                noBtn.removeEventListener('click', onNo);
                resolve(result);
            };
            const onYes = () => cleanup(true);
            const onNo = () => cleanup(false);
            yesBtn.addEventListener('click', onYes);
            noBtn.addEventListener('click', onNo);
        });
    },

    // Map old URL paths to tab names (for bookmarks)
    getTabFromPath(path) {
        const map = {
            '/': 'dashboard',
            '/index.html': 'dashboard',
            '/config.html': 'config',
            '/network.html': 'hosts',
            '/netkb.html': 'hosts',
            '/credentials.html': 'loot',
            '/loot.html': 'loot',
            '/bjorn.html': 'display'
        };
        return map[path] || null;
    },

    switchToLootSubTab(sub) {
        // Force tab switch even if already on loot (switchTab skips same-tab)
        if (this.activeTab !== 'loot') {
            this.switchTab('loot');
        }
        if (this.tabs.loot && this.tabs.loot.activateSubTab) {
            this.tabs.loot.activateSubTab(sub);
        }
    },

    async loadTheme() {
        try {
            var data = await this.api('/api/theme');
            this.theme = data;

            var web = data.web || {};
            var root = document.documentElement.style;

            // Map theme keys to CSS custom properties
            var varMap = {
                'bg_dark': '--bg-dark',
                'bg_surface': '--bg-surface',
                'bg_elevated': '--bg-elevated',
                'accent': '--gold',
                'accent_bright': '--gold-bright',
                'accent_dim': '--gold-dim',
                'text_primary': '--text-primary',
                'text_secondary': '--text-secondary',
                'text_muted': '--text-muted',
                'border': '--border',
                'border_light': '--border-light',
                'glow': '--glow-gold',
                'font_title': '--font-viking'
            };

            for (var key in varMap) {
                if (web[key]) {
                    root.setProperty(varMap[key], web[key]);
                }
            }

            // Inject dynamic @font-face for theme title font
            var fontStyle = document.getElementById('theme-font-style');
            if (!fontStyle) {
                fontStyle = document.createElement('style');
                fontStyle.id = 'theme-font-style';
                document.head.appendChild(fontStyle);
            }
            fontStyle.textContent = "@font-face { font-family: 'ThemeTitle'; src: url('" +
                (data.font_url || '/api/theme_font') + "') format('truetype'); font-display: swap; }";

            // Update document title
            if (data.web_title) {
                document.title = data.web_title;
            }

            // Update the Display tab's nav label dynamically
            var displayLabel = document.getElementById('nav-label-display');
            if (displayLabel && web.nav_label_display) {
                displayLabel.textContent = web.nav_label_display;
            }
        } catch (e) {
            console.error('Failed to load theme:', e);
        }
    }
};

// Auto-init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
    // Check if we arrived via an old URL (no hash but a specific path)
    if (!location.hash && location.pathname !== '/') {
        const mapped = App.getTabFromPath(location.pathname);
        if (mapped) location.hash = '#' + mapped;
    }
    App.init();
});
