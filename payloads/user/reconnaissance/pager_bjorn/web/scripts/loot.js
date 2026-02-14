/* ========================================
   Loot Tab - Credentials + Files + Logs
   ======================================== */
'use strict';

const LootTab = {
    activeSubTab: 'credentials',
    expandedPaths: new Set(),

    init() {
        const panel = document.getElementById('tab-loot');
        panel.innerHTML = `
            <div class="loot-panel">
                <div class="sub-tabs">
                    <button class="sub-tab active" data-sub="credentials">Credentials</button>
                    <button class="sub-tab" data-sub="files">Stolen Files</button>
                    <button class="sub-tab" data-sub="logs">Attack Logs</button>
                </div>
                <div id="loot-credentials" class="sub-panel active"></div>
                <div id="loot-files" class="sub-panel"></div>
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
