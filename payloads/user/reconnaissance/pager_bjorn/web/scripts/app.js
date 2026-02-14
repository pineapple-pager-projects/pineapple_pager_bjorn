/* ========================================
   Bjorn Cyberviking - SPA Core
   ======================================== */
'use strict';

const App = {
    activeTab: null,
    tabs: {},
    pollTimers: {},

    init() {
        // Bind nav clicks
        document.querySelectorAll('.nav-item').forEach(el => {
            el.addEventListener('click', e => {
                e.preventDefault();
                this.switchTab(el.dataset.tab);
            });
        });

        // Hash change handling
        window.addEventListener('hashchange', () => {
            const tab = location.hash.slice(1);
            if (tab && this.tabs[tab]) this.switchTab(tab);
        });

        // Initialize all registered tabs
        Object.keys(this.tabs).forEach(id => {
            if (this.tabs[id].init) this.tabs[id].init();
        });

        // Restore last tab or use hash or default to dashboard
        const hash = location.hash.slice(1);
        const saved = localStorage.getItem('bjorn_active_tab');
        const initial = (hash && this.tabs[hash]) ? hash
                      : (saved && this.tabs[saved]) ? saved
                      : 'dashboard';
        this.switchTab(initial);
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
            '/network.html': 'network',
            '/netkb.html': 'network',
            '/credentials.html': 'loot',
            '/loot.html': 'loot',
            '/bjorn.html': 'bjorn'
        };
        return map[path] || null;
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
