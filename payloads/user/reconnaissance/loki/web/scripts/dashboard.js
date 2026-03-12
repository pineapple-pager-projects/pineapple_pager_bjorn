/* ========================================
   Dashboard Tab - Stats + Live Console
   ======================================== */
'use strict';

const DashboardTab = {
    panel: null,
    statEls: {},
    // Console state
    lastTimestamp: null,
    autoScroll: true,
    levelFilter: 'ALL',
    maxLines: 2000,
    logOutput: null,
    scrollBtn: null,
    lineCount: 0,
    refreshingLogs: false,

    init() {
        this.panel = document.getElementById('tab-dashboard');
        this.panel.innerHTML = `
            <div class="dashboard-status">
                <div class="status-main" id="dash-orch-status">IDLE</div>
                <div class="status-detail" id="dash-status-detail"></div>
            </div>
            <div class="stats-grid">
                <div class="stat-card" data-stat="targetnbr">
                    <div class="stat-value" id="stat-targets">0</div>
                    <div class="stat-label">Targets</div>
                </div>
                <div class="stat-card" data-stat="crednbr">
                    <div class="stat-value" id="stat-creds">0</div>
                    <div class="stat-label">Credentials</div>
                </div>
                <div class="stat-card" data-stat="attacksnbr">
                    <div class="stat-value" id="stat-attacks">0</div>
                    <div class="stat-label">Attacks</div>
                </div>
                <div class="stat-card" data-stat="vulnnbr">
                    <div class="stat-value" id="stat-vulns">0</div>
                    <div class="stat-label">Vulns</div>
                </div>
                <div class="stat-card" data-stat="portnbr">
                    <div class="stat-value" id="stat-ports">0</div>
                    <div class="stat-label">Ports</div>
                </div>
                <div class="stat-card" data-stat="datanbr">
                    <div class="stat-value" id="stat-data">0</div>
                    <div class="stat-label">Data Stolen</div>
                </div>
                <div class="stat-card" data-stat="zombiesnbr">
                    <div class="stat-value" id="stat-zombies">0</div>
                    <div class="stat-label">Zombies</div>
                </div>
                <div class="stat-card" data-stat="levelnbr">
                    <div class="stat-value" id="stat-level">0</div>
                    <div class="stat-label">Level</div>
                </div>
                <div class="stat-card" data-stat="coinnbr">
                    <div class="stat-value" id="stat-gold">0</div>
                    <div class="stat-label">Gold</div>
                </div>
                <div class="stat-card" data-stat="networkkbnbr">
                    <div class="stat-value" id="stat-netkb">0</div>
                    <div class="stat-label">NetKB</div>
                </div>
            </div>
            <div class="dashboard-console">
                <div class="console-controls">
                    <div class="filter-buttons">
                        <button class="filter-btn active" data-level="ALL">ALL</button>
                        <button class="filter-btn" data-level="INFO">INFO</button>
                        <button class="filter-btn" data-level="WARNING">WARN</button>
                        <button class="filter-btn" data-level="ERROR">ERROR</button>
                    </div>
                    <div class="console-actions">
                        <button class="btn btn-sm auto-scroll-on" id="dash-auto-scroll-btn">Auto-scroll: ON</button>
                        <button class="btn btn-sm" id="dash-clear-console-btn">Clear</button>
                    </div>
                </div>
                <div id="dash-log-output" class="log-output"></div>
            </div>
        `;

        this.statEls = {
            targetnbr: document.getElementById('stat-targets'),
            crednbr: document.getElementById('stat-creds'),
            attacksnbr: document.getElementById('stat-attacks'),
            vulnnbr: document.getElementById('stat-vulns'),
            portnbr: document.getElementById('stat-ports'),
            datanbr: document.getElementById('stat-data'),
            zombiesnbr: document.getElementById('stat-zombies'),
            levelnbr: document.getElementById('stat-level'),
            coinnbr: document.getElementById('stat-gold'),
            networkkbnbr: document.getElementById('stat-netkb')
        };

        // Console elements
        this.logOutput = document.getElementById('dash-log-output');
        this.scrollBtn = document.getElementById('dash-auto-scroll-btn');

        // Filter button clicks
        this.panel.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                this.panel.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                this.levelFilter = btn.dataset.level;
                this.applyFilter();
            });
        });

        // Auto-scroll toggle
        this.scrollBtn.addEventListener('click', () => {
            this.autoScroll = !this.autoScroll;
            this.updateScrollBtn();
            if (this.autoScroll) {
                this.logOutput.scrollTop = this.logOutput.scrollHeight;
            }
        });

        // Detect scroll position
        this.logOutput.addEventListener('scroll', () => {
            const atBottom = this.logOutput.scrollHeight - this.logOutput.scrollTop - this.logOutput.clientHeight < 40;
            if (atBottom && !this.autoScroll) {
                this.autoScroll = true;
                this.updateScrollBtn();
            } else if (!atBottom && this.autoScroll) {
                this.autoScroll = false;
                this.updateScrollBtn();
            }
        });

        // Clear button
        document.getElementById('dash-clear-console-btn').addEventListener('click', () => {
            this.logOutput.innerHTML = '';
            this.lineCount = 0;
        });
    },

    updateScrollBtn() {
        this.scrollBtn.textContent = 'Auto-scroll: ' + (this.autoScroll ? 'ON' : 'OFF');
        this.scrollBtn.classList.toggle('auto-scroll-on', this.autoScroll);
    },

    activate() {
        this._statsCounter = 0;
        App.startPolling('dashboard', () => {
            this.refreshLogs();
            if (++this._statsCounter % 3 === 0) this.refreshStats();
        }, 1500);
    },

    deactivate() {
        App.stopPolling('dashboard');
    },

    async refreshStats() {
        try {
            const data = await App.api('/api/stats');
            Object.keys(this.statEls).forEach(key => {
                const el = this.statEls[key];
                if (el && data[key] !== undefined) {
                    const val = data[key];
                    el.textContent = val;
                    el.closest('.stat-card').classList.toggle('has-value', val > 0);
                }
            });

            if (data.web_title) {
                document.title = data.web_title;
            }

            const statusEl = document.getElementById('dash-orch-status');
            const detailEl = document.getElementById('dash-status-detail');
            if (statusEl) {
                statusEl.textContent = this.splitCamelCase(data.bjornstatustext) || 'IDLE';
            }
            if (detailEl) {
                const parts = [];
                if (data.bjornstatustext2) parts.push(this.splitCamelCase(data.bjornstatustext2));
                if (data.bjornorch_status && data.bjornorch_status !== 'IDLE') {
                    parts.push(this.splitCamelCase(data.bjornorch_status));
                }
                detailEl.textContent = parts.join(' - ');
            }
        } catch (e) {
            // Silent - will retry
        }
    },

    async refreshLogs() {
        if (this.refreshingLogs) return;
        this.refreshingLogs = true;
        try {
            let url = '/get_logs';
            if (this.lastTimestamp) {
                url += '?since=' + encodeURIComponent(this.lastTimestamp);
            }
            const data = await App.api(url);
            if (!data || data.includes('Waiting for logs') || data.includes('No log entries')) {
                return;
            }
            this.appendLines(data);
        } catch (e) {
            // Silent - will retry
        } finally {
            this.refreshingLogs = false;
        }
    },

    appendLines(text) {
        const lines = text.split('\n').filter(l => l.trim());
        if (lines.length === 0) return;

        for (let i = lines.length - 1; i >= 0; i--) {
            const m = lines[i].match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?)/);
            if (m) {
                this.lastTimestamp = m[1];
                break;
            }
        }

        const frag = document.createDocumentFragment();
        let added = 0;

        for (const line of lines) {
            const div = document.createElement('div');
            div.className = 'log-line ' + this.getLineClass(line);
            div.textContent = line;
            if (this.levelFilter !== 'ALL' && !this.matchesFilter(line)) {
                div.style.display = 'none';
            }
            frag.appendChild(div);
            added++;
        }

        this.logOutput.appendChild(frag);
        this.lineCount += added;

        while (this.lineCount > this.maxLines) {
            this.logOutput.removeChild(this.logOutput.firstChild);
            this.lineCount--;
        }

        if (this.autoScroll) {
            this.logOutput.scrollTop = this.logOutput.scrollHeight;
        }
    },

    getLineClass(line) {
        if (line.includes('[LIFECYCLE]')) return 'log-lifecycle';
        if (line.includes(' ERROR ')) return 'log-error';
        if (line.includes(' WARNING ')) return 'log-warning';
        if (line.includes(' INFO ')) return 'log-info';
        if (line.includes(' DEBUG ')) return 'log-debug';
        return '';
    },

    matchesFilter(line) {
        switch (this.levelFilter) {
            case 'ERROR': return line.includes(' ERROR ');
            case 'WARNING': return line.includes(' WARNING ');
            case 'INFO': return line.includes(' INFO ');
            default: return true;
        }
    },

    applyFilter() {
        const lines = this.logOutput.children;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (this.levelFilter === 'ALL') {
                line.style.display = '';
            } else {
                line.style.display = this.matchesFilter(line.textContent) ? '' : 'none';
            }
        }
    },

    splitCamelCase(str) {
        if (!str) return str;
        return str.replace(/([a-z])([A-Z])/g, '$1 $2')
                  .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2');
    }
};

App.registerTab('dashboard', DashboardTab);
