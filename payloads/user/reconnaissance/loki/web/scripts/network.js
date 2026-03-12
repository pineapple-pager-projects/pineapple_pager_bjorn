/* ========================================
   Network Tab - Host Table
   ======================================== */
'use strict';

const NetworkTab = {
    hosts: [],
    expandedHosts: new Set(),

    init() {
        const panel = document.getElementById('tab-hosts');
        panel.innerHTML = '<div id="network-table" class="network-panel"></div>';
    },

    activate() {
        App.startPolling('hosts', () => this.refresh(), 30000);
    },

    deactivate() {
        App.stopPolling('hosts');
    },

    async refresh() {
        // Skip refresh when a host profile is expanded to prevent collapse
        if (this.expandedHosts.size) return;
        try {
            const data = await App.api('/netkb_data_json');
            this.hosts = data.hosts || [];
            this.render();
        } catch (e) { /* retry */ }
    },

    render() {
        const container = document.getElementById('network-table');
        if (!this.hosts.length) {
            container.innerHTML = '<div class="empty-state">No hosts discovered yet.</div>';
            return;
        }

        container.innerHTML = this.hosts.map(h => {
            const alive = h.alive === '1';
            const hasCreds = this.hostHasCreds(h);
            const statusCls = hasCreds ? 'pwned' : (alive ? 'alive' : 'dead');
            const ports = (h.ports || '').replace(/;/g, ', ') || 'none';
            const hostname = h.hostname || '';
            const isExpanded = this.expandedHosts.has(h.ip);

            // Build attack status badges
            const actions = h.actions || {};
            const badges = this.renderBadges(actions);

            // Device classification
            const deviceType = h.device_type || '';
            const vendor = h.vendor || '';
            const dtClass = deviceType ? 'host-device-type dt-' + deviceType.toLowerCase().replace(/[^a-z]/g, '') : '';
            const deviceRow = (deviceType || vendor) ?
                '<div class="host-row-device">' +
                    (deviceType ? '<span class="' + dtClass + '">' + deviceType + '</span>' : '') +
                    (vendor && vendor !== 'Unknown' ? '<span class="host-vendor">' + vendor + '</span>' : '') +
                '</div>' : '';

            // Service tags (compact view)
            const serviceTags = this.renderServiceTags(h.services || '');

            // OS tag
            const osTag = h.os ? '<span class="os-tag">' + this.escapeHtml(h.os) + '</span>' : '';

            // Expanded host profile
            const profileHtml = isExpanded ? this.renderHostProfile(h) : '';

            return `
                <div class="host-card ${statusCls}${isExpanded ? ' expanded' : ''}" data-ip="${h.ip}">
                    <div class="host-row-main" onclick="NetworkTab.toggleHostDetail('${h.ip}')" style="cursor:pointer">
                        <div class="host-status ${statusCls}"></div>
                        <div class="host-info">
                            <span class="host-ip">${h.ip}</span>
                            ${hostname ? '<span class="host-name">' + hostname + '</span>' : ''}
                            <span class="host-mac">${h.mac || ''}</span>
                        </div>
                        <div class="host-ports">${ports}</div>
                    </div>
                    ${serviceTags || osTag ? '<div class="host-row-services">' + serviceTags + osTag + '</div>' : ''}
                    ${deviceRow}
                    ${badges ? '<div class="host-row-attacks">' + badges + '</div>' : ''}
                    ${profileHtml}
                </div>
            `;
        }).join('');
    },

    renderServiceTags(servicesStr) {
        if (!servicesStr) return '';
        const parts = servicesStr.split(';').filter(s => s.trim());
        if (!parts.length) return '';
        return parts.map(part => {
            const [port, svc] = part.split(':', 2);
            // Skip malformed entries (port must be numeric)
            if (!port || !/^\d+$/.test(port.trim())) return '';
            const label = this.stripControl(svc || port);
            if (!label) return '';
            return '<span class="service-tag">' + this.escapeHtml(label) + '</span>';
        }).join('');
    },

    toggleHostDetail(ip) {
        if (this.expandedHosts.has(ip)) {
            this.expandedHosts.delete(ip);
        } else {
            this.expandedHosts.add(ip);
        }
        this.render();
        // Load loot summary for expanded host
        if (this.expandedHosts.has(ip)) {
            this.loadHostLootSummary(ip);
        }
    },

    async loadHostLootSummary(ip) {
        const safeId = ip.replace(/\./g, '-');
        const container = document.getElementById('host-loot-' + safeId);
        if (!container || container.dataset.loaded) return;
        try {
            const data = await App.api('/api/host_loot_summary/' + ip);
            const items = [
                { key: 'vulns', label: 'vulnerabilities', sub: 'vulns' },
                { key: 'credentials', label: 'credentials', sub: 'credentials' },
                { key: 'stolen_files', label: 'stolen files', sub: 'files' }
            ];
            items.forEach(item => {
                const badge = container.querySelector('[data-loot="' + item.key + '"]');
                if (!badge) return;
                const count = data[item.key] || 0;
                badge.querySelector('.loot-count-num').textContent = count;
                if (count === 0) badge.classList.add('dimmed');
                else badge.classList.remove('dimmed');
            });
        } catch (e) {
            // Leave "--" placeholders on error
        }
        container.dataset.loaded = '1';
    },

    renderHostProfile(h) {
        const safeId = h.ip.replace(/\./g, '-');

        // Parse services into table rows
        let servicesHtml = '';
        if (h.services) {
            const parts = h.services.split(';').filter(s => s.trim());
            if (parts.length) {
                // Filter to valid entries (port must be numeric)
                const validParts = parts.filter(part => {
                    const [port] = part.split(':', 2);
                    return port && /^\d+$/.test(port.trim());
                });
                if (validParts.length) {
                    servicesHtml = '<table class="services-table"><thead><tr><th>Port</th><th>Service</th><th>Version</th></tr></thead><tbody>';
                    validParts.forEach(part => {
                        const [port, svc] = part.split(':', 2);
                        let serviceName = '', version = '';
                        if (svc) {
                            const slashIdx = svc.indexOf('/');
                            if (slashIdx !== -1) {
                                serviceName = svc.substring(0, slashIdx);
                                version = this.stripControl(svc.substring(slashIdx + 1));
                            } else {
                                serviceName = svc;
                            }
                        }
                        servicesHtml += '<tr><td>' + this.escapeHtml(port) + '/tcp</td><td>' +
                            this.escapeHtml(serviceName) + '</td><td>' + this.escapeHtml(version) + '</td></tr>';
                    });
                    servicesHtml += '</tbody></table>';
                }
            }
        }

        // Attack results
        const actions = h.actions || {};
        const attackHtml = this.renderBadges(actions);

        return `
            <div class="host-profile">
                <div class="host-profile-actions">
                    <button class="btn btn-sm export-btn" onclick="event.stopPropagation(); NetworkTab.exportHost('${this.escapeHtml(h.ip)}')">Export Report</button>
                </div>
                <div class="host-profile-section">
                    <div class="host-profile-row">
                        <span class="host-profile-label">IP:</span>
                        <span class="host-profile-value">${this.escapeHtml(h.ip)}</span>
                    </div>
                    ${h.hostname ? '<div class="host-profile-row"><span class="host-profile-label">Hostname:</span><span class="host-profile-value">' + this.escapeHtml(h.hostname) + '</span></div>' : ''}
                    <div class="host-profile-row">
                        <span class="host-profile-label">MAC:</span>
                        <span class="host-profile-value">${this.escapeHtml(h.mac || 'Unknown')}</span>
                    </div>
                    ${h.vendor && h.vendor !== 'Unknown' ? '<div class="host-profile-row"><span class="host-profile-label">Vendor:</span><span class="host-profile-value">' + this.escapeHtml(h.vendor) + '</span></div>' : ''}
                    ${h.device_type ? '<div class="host-profile-row"><span class="host-profile-label">Type:</span><span class="host-profile-value">' + this.escapeHtml(h.device_type) + '</span></div>' : ''}
                    ${h.os ? '<div class="host-profile-row"><span class="host-profile-label">OS:</span><span class="host-profile-value">' + this.escapeHtml(h.os) + '</span></div>' : ''}
                    <div class="host-profile-row">
                        <span class="host-profile-label">Status:</span>
                        <span class="host-profile-value">${h.alive === '1' ? 'ALIVE' : 'DOWN'}</span>
                    </div>
                </div>
                ${servicesHtml ? '<div class="host-profile-section"><div class="host-profile-section-title">Services</div>' + servicesHtml + '</div>' : ''}
                <div class="host-profile-section">
                    <div class="host-profile-section-title">Loot Summary</div>
                    <div id="host-loot-${safeId}" class="host-loot-summary">
                        <span class="loot-count-badge" data-loot="vulns" onclick="event.stopPropagation(); App.switchToLootSubTab('vulns')">
                            <span class="loot-count-num">--</span> vulnerabilities
                        </span>
                        <span class="loot-count-badge" data-loot="credentials" onclick="event.stopPropagation(); App.switchToLootSubTab('credentials')">
                            <span class="loot-count-num">--</span> credentials
                        </span>
                        <span class="loot-count-badge" data-loot="stolen_files" onclick="event.stopPropagation(); App.switchToLootSubTab('files')">
                            <span class="loot-count-num">--</span> stolen files
                        </span>
                    </div>
                </div>
                ${attackHtml ? '<div class="host-profile-section"><div class="host-profile-section-title">Attack Results</div><div class="host-row-attacks">' + attackHtml + '</div></div>' : ''}
            </div>
        `;
    },

    renderBadges(actions) {
        // One badge per action that ran. Green = success, red = ran but failed.
        const actionLabels = {
            'SSHBruteforce': 'SSH Brute',
            'FTPBruteforce': 'FTP Brute',
            'TelnetBruteforce': 'Telnet Brute',
            'SMBBruteforce': 'SMB Brute',
            'RDPBruteforce': 'RDP Brute',
            'SQLBruteforce': 'SQL Brute',
            'StealFilesSSH': 'SSH Loot',
            'StealFilesFTP': 'FTP Loot',
            'StealFilesTelnet': 'Telnet Loot',
            'StealFilesSMB': 'SMB Loot',
            'StealDataSQL': 'SQL Loot',
            'NmapVulnScanner': 'Vuln Scan'
        };
        const actionOrder = [
            'SSHBruteforce', 'StealFilesSSH',
            'FTPBruteforce', 'StealFilesFTP',
            'TelnetBruteforce', 'StealFilesTelnet',
            'SMBBruteforce', 'StealFilesSMB',
            'RDPBruteforce',
            'SQLBruteforce', 'StealDataSQL',
            'NmapVulnScanner'
        ];

        const badges = [];
        for (const key of actionOrder) {
            const val = actions[key] || '';
            if (!val) continue;
            const ok = val.toLowerCase().includes('success');
            const cls = ok ? 'success' : 'failed';
            badges.push('<span class="attack-badge ' + cls + '">' + actionLabels[key] + '</span>');
        }
        return badges.join('');
    },

    hostHasCreds(host) {
        const actions = host.actions || {};
        return Object.keys(actions).some(k =>
            k.includes('Bruteforce') && (actions[k] || '').toLowerCase().includes('success')
        );
    },

    exportHost(ip) {
        window.location.href = '/api/export_host/' + encodeURIComponent(ip);
    },

    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    stripControl(str) {
        // Strip literal \xNN and \xFF escape sequences and ANSI codes
        return str.replace(/\\x[0-9A-Fa-f]{2}/g, '')
                  .replace(/\\u[0-9A-Fa-f]{4}/g, '')
                  .replace(/\x1B\[[0-9;]*[A-Za-z]/g, '')
                  .replace(/[\x00-\x1f\x7f-\x9f]/g, '')
                  .trim();
    }
};

App.registerTab('hosts', NetworkTab);
