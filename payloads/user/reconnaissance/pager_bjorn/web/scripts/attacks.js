/* ========================================
   Attacks Tab - Timeline + Manual Mode
   ======================================== */
'use strict';

var AttacksTab = {
    isManualMode: false,
    isAttackRunning: false,
    attackLogInterval: null,
    netkbData: null,
    actionPorts: {},
    portToActions: {},
    actionDisplayNames: {},

    init() {
        var panel = document.getElementById('tab-attacks');
        panel.innerHTML = '<div class="attacks-panel">' +
            '<div class="flex items-center justify-between mb-8">' +
            '<span class="section-title" style="margin:0">Manual Attack Mode</span>' +
            '<button class="btn" id="manual-mode-toggle">Enable Manual Mode</button>' +
            '</div>' +
            '<div class="manual-controls disabled" id="manual-controls">' +
            '<div class="manual-row">' +
            '<select class="form-input" id="atk-network" title="Network"></select>' +
            '<select class="form-input" id="atk-ip" title="Target IP"></select>' +
            '</div>' +
            '<div class="manual-row">' +
            '<select class="form-input" id="atk-port" title="Port"></select>' +
            '<select class="form-input" id="atk-action" title="Action"></select>' +
            '</div>' +
            '<div class="manual-row">' +
            '<button class="btn btn-gold" id="atk-execute">Execute</button>' +
            '<button class="btn btn-danger btn-sm" id="atk-clear-hosts">Clear Hosts</button>' +
            '</div></div>' +
            '<div class="attack-log" id="attack-log-output"></div>' +
            '<hr class="divider">' +
            '<div class="section-title">Attack Timeline</div>' +
            '<div class="timeline" id="attack-timeline"></div>' +
            '</div>';

        document.getElementById('manual-mode-toggle').addEventListener('click', () => this.toggleManualMode());
        document.getElementById('atk-execute').addEventListener('click', () => this.executeAttack());
        document.getElementById('atk-clear-hosts').addEventListener('click', () => this.clearHosts());
        document.getElementById('atk-ip').addEventListener('change', () => this.updatePortDropdown());
        document.getElementById('atk-port').addEventListener('change', () => this.onPortSelected());
    },

    activate() {
        this.loadOptions();
        App.startPolling('attacks', () => this.refreshTimeline(), 15000);
    },

    deactivate() {
        App.stopPolling('attacks');
    },

    async toggleManualMode() {
        var btn = document.getElementById('manual-mode-toggle');
        var controls = document.getElementById('manual-controls');

        if (!this.isManualMode) {
            this.isManualMode = true;
            btn.textContent = 'Disable Manual Mode';
            btn.classList.add('btn-danger');
            controls.classList.remove('disabled');
            try { await App.post('/stop_orchestrator'); } catch (e) {}
            App.toast('Manual mode enabled - orchestrator paused', 'info');
            this.loadOptions();
        } else {
            if (this.isAttackRunning) {
                App.toast('Wait for current attack to finish', 'error');
                return;
            }
            this.isManualMode = false;
            btn.textContent = 'Enable Manual Mode';
            btn.classList.remove('btn-danger');
            controls.classList.add('disabled');
            this.stopAttackLog();
            document.getElementById('attack-log-output').classList.remove('visible');
            try { await App.post('/start_orchestrator'); } catch (e) {}
            App.toast('Manual mode disabled - orchestrator resumed', 'info');
        }
    },

    async loadOptions() {
        try {
            var nets = await App.api('/get_networks');
            var netDrop = document.getElementById('atk-network');
            if (nets.networks && nets.networks.length) {
                netDrop.innerHTML = nets.networks.map(n =>
                    '<option value="' + n.network + '">' + n.display + '</option>'
                ).join('');
            } else {
                netDrop.innerHTML = '<option value="">No networks</option>';
            }
        } catch (e) {}

        try {
            var data = await App.api('/netkb_data_json');
            this.netkbData = data;
            this.actionPorts = data.action_ports || {};
            this.portToActions = data.port_to_actions || {};
            this.actionDisplayNames = data.action_display_names || {};

            var ipDrop = document.getElementById('atk-ip');
            if (data.ips && data.ips.length) {
                ipDrop.innerHTML = '<option value="network_scan">Scan Network</option>' +
                    data.ips.map(ip => '<option value="' + ip + '">' + ip + '</option>').join('');
                ipDrop.value = data.ips[0];
            } else {
                ipDrop.innerHTML = '<option value="network_scan">Scan Network (find hosts)</option>';
            }

            this.populateActions();
            this.updatePortDropdown();
        } catch (e) {}
    },

    populateActions() {
        var drop = document.getElementById('atk-action');
        if (this.netkbData && this.netkbData.actions) {
            drop.innerHTML = this.netkbData.actions.map(a => {
                var name = this.actionDisplayNames[a] || a;
                return '<option value="' + a + '">' + name + '</option>';
            }).join('');
        }
    },

    onPortSelected() {
        var port = document.getElementById('atk-port').value;
        var actionDrop = document.getElementById('atk-action');
        if (!port || port === 'port_scan') return;
        var actions = this.portToActions[port];
        if (actions && actions.length) actionDrop.value = actions[0];
    },

    updatePortDropdown() {
        var ip = document.getElementById('atk-ip').value;
        var portDrop = document.getElementById('atk-port');
        var actionDrop = document.getElementById('atk-action');

        if (ip === 'network_scan' || !ip) {
            portDrop.innerHTML = '<option value="">N/A</option>';
            actionDrop.innerHTML = '<option value="">N/A</option>';
            return;
        }

        if (actionDrop.value === '') this.populateActions();

        var protocols = {
            '21': 'FTP', '22': 'SSH', '23': 'Telnet', '80': 'HTTP',
            '443': 'HTTPS', '445': 'SMB', '1433': 'MSSQL', '3306': 'MySQL',
            '3389': 'RDP', '5432': 'PostgreSQL'
        };

        var ports = [];
        if (this.netkbData && this.netkbData.ports && this.netkbData.ports[ip]) {
            ports = this.netkbData.ports[ip];
        }

        if (!ports.length) {
            portDrop.innerHTML = '<option value="port_scan">Scan Ports</option>';
            return;
        }

        portDrop.innerHTML = ports.map(p => {
            var proto = protocols[p] || '';
            return '<option value="' + p + '">' + p + (proto ? ' (' + proto + ')' : '') + '</option>';
        }).join('') + '<option value="port_scan">Rescan Ports</option>';

        this.onPortSelected();
    },

    async executeAttack() {
        if (this.isAttackRunning) {
            App.toast('Attack already running', 'error');
            return;
        }

        var ip = document.getElementById('atk-ip').value;
        var port = document.getElementById('atk-port').value;
        var action = document.getElementById('atk-action').value;
        var network = document.getElementById('atk-network').value;

        if (ip === 'network_scan' || !ip) {
            return this.runAttack({ ip: '', port: '', action: 'NetworkScanner', network: network }, 'NetworkScanner');
        }
        if (port === 'port_scan') {
            return this.runAttack({ ip: ip, port: '', action: 'PortScanner' }, 'PortScanner');
        }
        if (!port || !action) {
            App.toast('Select a port and action', 'error');
            return;
        }
        return this.runAttack({ ip: ip, port: port, action: action }, action);
    },

    async runAttack(params, actionName) {
        this.isAttackRunning = true;
        this.startAttackLog();

        try {
            await App.post('/mark_action_start');
            await App.post('/execute_manual_attack', params);
            this.appendAttackLog('--- ' + actionName + ' started ---\n');
            this.waitForCompletion(actionName);
        } catch (e) {
            this.isAttackRunning = false;
            this.stopAttackLog();
            App.toast('Attack failed: ' + e.message, 'error');
        }
    },

    startAttackLog() {
        var el = document.getElementById('attack-log-output');
        el.innerHTML = '';
        el.classList.add('visible');
        this.stopAttackLog();
        this.fetchAttackLogs();
        this.attackLogInterval = setInterval(() => this.fetchAttackLogs(), 500);
    },

    stopAttackLog() {
        if (this.attackLogInterval) {
            clearInterval(this.attackLogInterval);
            this.attackLogInterval = null;
        }
    },

    async fetchAttackLogs() {
        try {
            var data = await App.api('/get_logs?current=1');
            if (!data || data.includes('Waiting for logs')) return;
            var el = document.getElementById('attack-log-output');
            el.textContent = data;
            el.scrollTop = el.scrollHeight;
        } catch (e) {}
    },

    appendAttackLog(text) {
        var el = document.getElementById('attack-log-output');
        el.textContent += text;
        el.scrollTop = el.scrollHeight;
    },

    waitForCompletion(actionName) {
        var self = this;
        var check = setInterval(function() {
            var el = document.getElementById('attack-log-output');
            var text = el.textContent || '';
            if (text.includes('[LIFECYCLE]') && text.includes('ENDED')) {
                clearInterval(check);
                self.isAttackRunning = false;
                self.stopAttackLog();
                self.fetchAttackLogs();
                self.loadOptions();
                self.refreshTimeline();
                App.toast('Attack completed', 'success');
            }
        }, 1000);

        // Safety timeout 10 min
        setTimeout(function() {
            clearInterval(check);
            if (self.isAttackRunning) {
                self.isAttackRunning = false;
                self.stopAttackLog();
                App.toast('Attack timed out', 'error');
            }
        }, 600000);
    },

    async clearHosts() {
        if (!await App.confirm('Clear all discovered hosts?')) return;
        try {
            await App.post('/clear_hosts');
            App.toast('Hosts cleared', 'success');
            this.loadOptions();
        } catch (e) {
            App.toast('Failed: ' + e.message, 'error');
        }
    },

    /* --- Timeline --- */
    async refreshTimeline() {
        try {
            var data = await App.api('/netkb_data_json');
            var hosts = data.hosts || [];
            var events = [];

            hosts.forEach(host => {
                var actions = host.actions || {};
                Object.keys(actions).forEach(key => {
                    var val = actions[key];
                    if (!val || !val.trim()) return;
                    var m = val.match(/(success|failed)_(\d{8})_(\d{6})/);
                    if (m) {
                        var ts = m[2].slice(0, 4) + '-' + m[2].slice(4, 6) + '-' + m[2].slice(6) +
                                 ' ' + m[3].slice(0, 2) + ':' + m[3].slice(2, 4) + ':' + m[3].slice(4);
                        events.push({
                            timestamp: ts,
                            sortKey: m[2] + m[3],
                            action: key,
                            ip: host.ip,
                            status: m[1]
                        });
                    }
                });
            });

            events.sort((a, b) => b.sortKey.localeCompare(a.sortKey));

            var container = document.getElementById('attack-timeline');
            if (!events.length) {
                container.innerHTML = '<div class="empty-state">No attack history yet.</div>';
                return;
            }

            container.innerHTML = events.slice(0, 100).map(ev => {
                var displayName = (data.action_display_names || {})[ev.action] || ev.action;
                return '<div class="timeline-item">' +
                    '<div class="timeline-dot ' + ev.status + '"></div>' +
                    '<div class="timeline-content">' +
                    '<div class="timeline-action">' + displayName + '</div>' +
                    '<div class="timeline-target">' + ev.ip + ' - ' + ev.status + '</div>' +
                    '<div class="timeline-time">' + ev.timestamp + '</div>' +
                    '</div></div>';
            }).join('');
        } catch (e) { /* retry */ }
    }
};

App.registerTab('attacks', AttacksTab);
