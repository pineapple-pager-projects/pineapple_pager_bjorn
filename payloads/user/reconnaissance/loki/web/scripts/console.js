/* ========================================
   Console Tab - Live Log Viewer (Improved)
   ----------------------------------------
   Key improvements over old implementation:
   - NEVER stops polling when text is selected
   - Uses DOM appendChild (not innerHTML) so
     existing text selection is preserved
   - Incremental fetch via ?since= timestamp
   - Auto-scroll only when user is at bottom
   - Level filter buttons
   ======================================== */
'use strict';

const ConsoleTab = {
    lastTimestamp: null,
    autoScroll: true,
    levelFilter: 'ALL',
    maxLines: 2000,
    output: null,
    scrollBtn: null,
    lineCount: 0,
    initialized: false,
    refreshing: false,

    init() {
        const panel = document.getElementById('tab-console');
        panel.innerHTML = `
            <div class="console-panel">
                <div class="console-controls">
                    <div class="filter-buttons">
                        <button class="filter-btn active" data-level="ALL">ALL</button>
                        <button class="filter-btn" data-level="INFO">INFO</button>
                        <button class="filter-btn" data-level="WARNING">WARN</button>
                        <button class="filter-btn" data-level="ERROR">ERROR</button>
                    </div>
                    <div class="console-actions">
                        <button class="btn btn-sm auto-scroll-on" id="auto-scroll-btn">Auto-scroll: ON</button>
                        <button class="btn btn-sm" id="clear-console-btn">Clear</button>
                    </div>
                </div>
                <div id="log-output" class="log-output"></div>
            </div>
        `;

        this.output = document.getElementById('log-output');
        this.scrollBtn = document.getElementById('auto-scroll-btn');

        // Filter button clicks
        panel.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                panel.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
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
                this.output.scrollTop = this.output.scrollHeight;
            }
        });

        // Detect scroll position to auto-toggle auto-scroll
        this.output.addEventListener('scroll', () => {
            const atBottom = this.output.scrollHeight - this.output.scrollTop - this.output.clientHeight < 40;
            if (atBottom && !this.autoScroll) {
                this.autoScroll = true;
                this.updateScrollBtn();
            } else if (!atBottom && this.autoScroll) {
                this.autoScroll = false;
                this.updateScrollBtn();
            }
        });

        // Clear button
        document.getElementById('clear-console-btn').addEventListener('click', () => {
            this.output.innerHTML = '';
            this.lineCount = 0;
            this.lastTimestamp = null;
        });

        this.initialized = true;
    },

    updateScrollBtn() {
        this.scrollBtn.textContent = 'Auto-scroll: ' + (this.autoScroll ? 'ON' : 'OFF');
        this.scrollBtn.classList.toggle('auto-scroll-on', this.autoScroll);
    },

    activate() {
        App.startPolling('console', () => this.refresh(), 1500);
    },

    deactivate() {
        App.stopPolling('console');
    },

    async refresh() {
        if (this.refreshing) return;
        this.refreshing = true;
        try {
            let url = '/get_logs';
            if (this.lastTimestamp) {
                url += '?since=' + encodeURIComponent(this.lastTimestamp);
            }
            const data = await App.api(url);

            // Skip placeholder messages
            if (!data || data.includes('Waiting for logs') || data.includes('No log entries')) {
                return;
            }

            this.appendLines(data);
        } catch (e) {
            // Silent - will retry
        } finally {
            this.refreshing = false;
        }
    },

    appendLines(text) {
        const lines = text.split('\n').filter(l => l.trim());
        if (lines.length === 0) return;

        // Update last timestamp from the final line
        for (let i = lines.length - 1; i >= 0; i--) {
            const m = lines[i].match(/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?)/);
            if (m) {
                this.lastTimestamp = m[1];
                break;
            }
        }

        // Build fragment of new line elements (does NOT touch existing DOM)
        const frag = document.createDocumentFragment();
        let added = 0;

        for (const line of lines) {
            const div = document.createElement('div');
            div.className = 'log-line ' + this.getLineClass(line);
            div.textContent = line;

            // Apply current filter visibility
            if (this.levelFilter !== 'ALL' && !this.matchesFilter(line)) {
                div.style.display = 'none';
            }

            frag.appendChild(div);
            added++;
        }

        // Append all at once (single reflow)
        this.output.appendChild(frag);
        this.lineCount += added;

        // Trim excess lines from top
        while (this.lineCount > this.maxLines) {
            this.output.removeChild(this.output.firstChild);
            this.lineCount--;
        }

        // Auto-scroll if enabled (selection is preserved because
        // we only scrolled, not re-rendered)
        if (this.autoScroll) {
            this.output.scrollTop = this.output.scrollHeight;
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
        // Show/hide existing lines based on filter (no re-render)
        const lines = this.output.children;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (this.levelFilter === 'ALL') {
                line.style.display = '';
            } else {
                line.style.display = this.matchesFilter(line.textContent) ? '' : 'none';
            }
        }
    }
};

App.registerTab('console', ConsoleTab);
