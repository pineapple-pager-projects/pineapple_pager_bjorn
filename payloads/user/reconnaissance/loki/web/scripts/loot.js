/* ========================================
   Loot Tab - Credentials + Files + Vulns + Logs
   ======================================== */
'use strict';

const LootTab = {
    activeSubTab: 'credentials',
    expandedPaths: new Set(),
    expandedVulnIPs: new Set(),

    init() {
        const panel = document.getElementById('tab-loot');
        panel.innerHTML = `
            <div class="loot-panel">
                <div class="sub-tabs">
                    <button class="sub-tab active" data-sub="credentials">Credentials</button>
                    <button class="sub-tab" data-sub="files">Stolen Files</button>
                    <button class="sub-tab" data-sub="vulns">Vulnerabilities</button>
                    <button class="sub-tab" data-sub="logs">Attack Logs</button>
                </div>
                <div id="loot-credentials" class="sub-panel active"></div>
                <div id="loot-files" class="sub-panel"></div>
                <div id="loot-vulns" class="sub-panel"></div>
                <div id="loot-logs" class="sub-panel"></div>
            </div>
        `;

        panel.querySelectorAll('.sub-tab').forEach(btn => {
            btn.addEventListener('click', () => {
                panel.querySelectorAll('.sub-tab').forEach(b => b.classList.remove('active'));
                panel.querySelectorAll('.sub-panel').forEach(p => p.classList.remove('active'));
                btn.classList.add('active');
                document.getElementById('loot-' + btn.dataset.sub).classList.add('active');
                this.activeSubTab = btn.dataset.sub;
                this.refresh();
            });
        });
    },

    activateSubTab(sub) {
        const panel = document.getElementById('tab-loot');
        if (!panel) return;
        const btn = panel.querySelector('.sub-tab[data-sub="' + sub + '"]');
        if (!btn) return;
        panel.querySelectorAll('.sub-tab').forEach(b => b.classList.remove('active'));
        panel.querySelectorAll('.sub-panel').forEach(p => p.classList.remove('active'));
        btn.classList.add('active');
        document.getElementById('loot-' + sub).classList.add('active');
        this.activeSubTab = sub;
        this.refresh();
    },

    activate() {
        App.startPolling('loot', () => this.refresh(), 10000);
    },

    deactivate() {
        App.stopPolling('loot');
    },

    async refresh() {
        switch (this.activeSubTab) {
            case 'credentials': return this.loadCredentials();
            case 'files': return this.loadFiles();
            case 'vulns':
                // Skip auto-refresh when a vuln detail is expanded to prevent collapse
                if (!this.expandedVulnIPs.size) return this.loadVulnerabilities();
                return;
            case 'logs': return this.loadLogs();
        }
    },

    /* --- Credentials --- */
    async loadCredentials() {
        try {
            const html = await App.api('/list_credentials');
            const container = document.getElementById('loot-credentials');
            if (!html || html.trim() === '<div class="credentials-container">\n</div>\n') {
                container.innerHTML = '<div class="empty-state">No credentials found yet.</div>';
                return;
            }
            // Restyle the server-rendered HTML with our new table classes
            container.innerHTML = html.replace(/class="styled-table/g, 'class="data-table')
                                      .replace(/<h2>/g, '<div class="cred-section"><h3>')
                                      .replace(/<\/h2>/g, '</h3>')
                                      .replace(/<\/table>/g, '</table></div>');
        } catch (e) {
            document.getElementById('loot-credentials').innerHTML = '<div class="empty-state">Error loading credentials.</div>';
        }
    },

    /* --- Stolen Files --- */
    async loadFiles() {
        try {
            const files = await App.api('/list_files');
            const container = document.getElementById('loot-files');
            if (!files || !files.length) {
                container.innerHTML = '<div class="empty-state">No stolen files yet.</div>';
                return;
            }
            container.innerHTML = '<ul class="loot-tree">' + this.renderFileTree(files, 'files') + '</ul>';
            this.restoreExpanded(container);
        } catch (e) {
            document.getElementById('loot-files').innerHTML = '<div class="empty-state">Error loading files.</div>';
        }
    },

    renderFileTree(items, prefix) {
        return items.map(item => {
            if (item.is_directory) {
                const children = item.children || [];
                const count = this.countFiles(children);
                const path = prefix + '/' + item.name;
                return '<li class="tree-node" data-path="' + path + '">' +
                    '<div class="tree-header" onclick="LootTab.toggleTree(this)">' +
                    '<span class="tree-icon">&#9654;</span>' +
                    '<span>' + item.name + '</span>' +
                    '<span class="tree-count">' + count + '</span>' +
                    '</div>' +
                    '<div class="tree-content"><ul>' + this.renderFileTree(children, path) + '</ul></div>' +
                    '</li>';
            } else {
                return '<li class="tree-file">' +
                    '<a href="/download_file?path=' + encodeURIComponent(item.path) + '" title="Download">' + item.name + '</a>' +
                    '</li>';
            }
        }).join('');
    },

    countFiles(items) {
        let c = 0;
        items.forEach(i => {
            if (i.is_directory) c += this.countFiles(i.children || []);
            else c++;
        });
        return c;
    },

    toggleTree(el) {
        const node = el.closest('.tree-node');
        node.classList.toggle('expanded');
        const path = node.dataset.path;
        if (path) {
            if (node.classList.contains('expanded')) {
                this.expandedPaths.add(path);
            } else {
                this.expandedPaths.delete(path);
            }
        }
    },

    restoreExpanded(container) {
        if (!this.expandedPaths.size) return;
        container.querySelectorAll('.tree-node[data-path]').forEach(node => {
            if (this.expandedPaths.has(node.dataset.path)) {
                node.classList.add('expanded');
            }
        });
    },

    /* --- Vulnerabilities --- */
    async loadVulnerabilities() {
        try {
            const data = await App.api('/api/vulnerabilities');
            const container = document.getElementById('loot-vulns');
            const summary = data.summary || [];

            if (!summary.length) {
                container.innerHTML = '<div class="empty-state">No vulnerabilities found yet. Run a vuln scan from the Attacks tab.</div>';
                return;
            }

            let headerExtra = '';
            if (data.kev_count > 0) {
                headerExtra = ' <span class="kev-badge">' + data.kev_count + ' KNOWN EXPLOITED</span>';
            }
            let html = '<div class="vuln-header">' +
                '<span class="vuln-stat">' + data.total_count + ' unique vulnerabilities across ' + data.hosts_scanned + ' hosts' + headerExtra + '</span>' +
                '</div>';
            html += '<table class="data-table vuln-table"><thead><tr>' +
                '<th>IP</th><th>Hostname</th><th>Ports</th><th>Vulnerabilities</th>' +
                '</tr></thead><tbody>';

            summary.forEach(entry => {
                const vulnList = entry.vulnerabilities.split('; ').filter(v => v.trim());
                const isExpanded = this.expandedVulnIPs.has(entry.ip);
                const toggleIcon = isExpanded ? '&#9660;' : '&#9654;';

                html += '<tr class="vuln-row clickable" onclick="LootTab.toggleVulnDetail(\'' + entry.ip + '\')">' +
                    '<td><span class="toggle-icon">' + toggleIcon + '</span> ' + entry.ip + '</td>' +
                    '<td>' + (entry.hostname || '-') + '</td>' +
                    '<td>' + (entry.port || '-') + '</td>' +
                    '<td>' + vulnList.length + ' finding' + (vulnList.length !== 1 ? 's' : '') + '</td>' +
                    '</tr>';

                // Expandable detail row
                html += '<tr class="vuln-detail-row" id="vuln-detail-' + entry.ip.replace(/\./g, '-') + '" style="display:' + (isExpanded ? 'table-row' : 'none') + ';">' +
                    '<td colspan="4"><div class="vuln-detail-content">';

                // Nmap detail container (loaded on demand)
                html += '<div class="vuln-nmap-output" id="vuln-nmap-' + entry.ip.replace(/\./g, '-') + '"></div>';
                html += '</div></td></tr>';
            });

            html += '</tbody></table>';
            container.innerHTML = html;
        } catch (e) {
            document.getElementById('loot-vulns').innerHTML = '<div class="empty-state">Error loading vulnerabilities.</div>';
        }
    },

    async toggleVulnDetail(ip) {
        const safeId = ip.replace(/\./g, '-');
        const detailRow = document.getElementById('vuln-detail-' + safeId);
        const detailContainer = document.getElementById('vuln-nmap-' + safeId);

        if (!detailRow) return;

        const isHidden = detailRow.style.display === 'none';
        detailRow.style.display = isHidden ? 'table-row' : 'none';

        if (isHidden) {
            this.expandedVulnIPs.add(ip);
            if (detailContainer && !detailContainer.dataset.loaded) {
                detailContainer.innerHTML = '<div class="loading">Loading...</div>';
                try {
                    const data = await App.api('/api/vulnerabilities/' + ip);
                    if (data && data.findings && data.findings.length) {
                        let html = '';
                        data.findings.forEach(f => {
                            const stateClass = f.state === 'VULNERABLE' ? 'vuln-confirmed' : 'vuln-likely';
                            html += '<div class="vuln-finding">';
                            // Port and service
                            if (f.port && f.port !== 'host') {
                                html += '<div class="vuln-port">' + this.escapeHtml(f.port) + (f.service ? ' (' + this.escapeHtml(f.service) + ')' : '') + '</div>';
                            }
                            // Title
                            if (f.title) {
                                html += '<div class="vuln-title">' + this.escapeHtml(f.title) + '</div>';
                            }
                            // State + Risk
                            html += '<div class="vuln-state ' + stateClass + '">' + this.escapeHtml(f.state);
                            if (f.risk) html += ' &mdash; Risk: ' + this.escapeHtml(f.risk);
                            html += '</div>';
                            // Threat intel badges (KEV, ransomware, CVSS)
                            if (f.kev || f.cvss_score != null) {
                                html += '<div class="vuln-threat-intel">';
                                if (f.kev) {
                                    html += '<span class="kev-badge">KNOWN EXPLOITED</span>';
                                }
                                if (f.ransomware_use === 'Known') {
                                    html += '<span class="ransomware-badge">RANSOMWARE</span>';
                                }
                                if (f.cvss_score != null) {
                                    let cvssClass = 'cvss-low';
                                    if (f.cvss_score >= 9.0) cvssClass = 'cvss-critical';
                                    else if (f.cvss_score >= 7.0) cvssClass = 'cvss-high';
                                    else if (f.cvss_score >= 4.0) cvssClass = 'cvss-medium';
                                    html += '<span class="cvss-badge ' + cvssClass + '">CVSS ' + f.cvss_score + '</span>';
                                }
                                html += '</div>';
                            }
                            if (f.required_action) {
                                html += '<div class="required-action">' + this.escapeHtml(f.required_action) + '</div>';
                            }
                            // CVEs
                            if (f.cves && f.cves.length) {
                                html += '<div class="vuln-cves">' + f.cves.map(c => '<span class="vuln-cve-tag">' + this.escapeHtml(c) + '</span>').join(' ') + '</div>';
                            }
                            // Description
                            if (f.description) {
                                html += '<div class="vuln-desc">' + this.escapeHtml(f.description) + '</div>';
                            }
                            // Disclosure date
                            if (f.disclosure_date) {
                                html += '<div class="vuln-date">Disclosed: ' + this.escapeHtml(f.disclosure_date) + '</div>';
                            }
                            html += '</div>';
                        });
                        detailContainer.innerHTML = html;
                    } else {
                        detailContainer.innerHTML = '<div class="empty-state">No structured findings. Run a new vuln scan to generate details.</div>';
                    }
                } catch (e) {
                    detailContainer.innerHTML = '<div class="empty-state">Error loading detail.</div>';
                }
                detailContainer.dataset.loaded = '1';
            }
        } else {
            this.expandedVulnIPs.delete(ip);
        }

        // Update toggle icon in parent row
        const parentRow = detailRow.previousElementSibling;
        if (parentRow) {
            const icon = parentRow.querySelector('.toggle-icon');
            if (icon) icon.innerHTML = isHidden ? '&#9660;' : '&#9654;';
        }
    },

    escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    },

    /* --- Attack Logs --- */
    async loadLogs() {
        try {
            const data = await App.api('/list_logs');
            const container = document.getElementById('loot-logs');
            const categories = data.categories || [];
            const uncategorized = data.uncategorized || [];

            if (!categories.length && !uncategorized.length) {
                container.innerHTML = '<div class="empty-state">No log files yet.</div>';
                return;
            }

            let html = '<ul class="loot-tree">';
            categories.forEach(cat => {
                var path = 'logs/' + cat.label;
                html += '<li class="tree-node" data-path="' + path + '">' +
                    '<div class="tree-header" onclick="LootTab.toggleTree(this)">' +
                    '<span class="tree-icon">&#9654;</span>' +
                    '<span>' + cat.label + '</span>' +
                    '<span class="tree-count">' + cat.logs.length + '</span>' +
                    '</div>' +
                    '<div class="tree-content"><ul>';
                cat.logs.forEach(log => {
                    html += '<li class="tree-file">' +
                        '<a href="/download_log?name=' + encodeURIComponent(log.name) + '" title="Download">' + log.name + '</a>' +
                        '<span class="file-size">' + log.size + '</span>' +
                        '</li>';
                });
                html += '</ul></div></li>';
            });

            if (uncategorized.length) {
                html += '<li class="tree-node" data-path="logs/Other Logs">' +
                    '<div class="tree-header" onclick="LootTab.toggleTree(this)">' +
                    '<span class="tree-icon">&#9654;</span>' +
                    '<span>Other Logs</span>' +
                    '<span class="tree-count">' + uncategorized.length + '</span>' +
                    '</div>' +
                    '<div class="tree-content"><ul>';
                uncategorized.forEach(log => {
                    html += '<li class="tree-file">' +
                        '<a href="/download_log?name=' + encodeURIComponent(log.name) + '" title="Download">' + log.name + '</a>' +
                        '<span class="file-size">' + log.size + '</span>' +
                        '</li>';
                });
                html += '</ul></div></li>';
            }

            html += '</ul>';
            container.innerHTML = html;
            this.restoreExpanded(container);
        } catch (e) {
            document.getElementById('loot-logs').innerHTML = '<div class="empty-state">Error loading logs.</div>';
        }
    }
};

App.registerTab('loot', LootTab);
