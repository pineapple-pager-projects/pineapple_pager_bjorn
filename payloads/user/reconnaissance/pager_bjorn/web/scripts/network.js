/* ========================================
   Network Tab - Host Table + SVG Topology
   ======================================== */
'use strict';

const NetworkTab = {
    hosts: [],
    view: 'table',
    detailEl: null,

    init() {
        const panel = document.getElementById('tab-network');
        panel.innerHTML = `
            <div class="network-panel">
                <div class="view-toggle">
                    <button class="btn active" data-view="table" id="net-view-table">Table</button>
                    <button class="btn" data-view="topology" id="net-view-topo">Topology</button>
                </div>
                <div id="network-table-view" class="network-view"></div>
                <div id="network-topology-view" class="network-view hidden" style="position:relative;">
                    <svg id="topology-svg"></svg>
                </div>
            </div>
        `;

        document.getElementById('net-view-table').addEventListener('click', () => this.setView('table'));
        document.getElementById('net-view-topo').addEventListener('click', () => this.setView('topology'));
    },

    setView(v) {
        this.view = v;
        document.getElementById('net-view-table').classList.toggle('active', v === 'table');
        document.getElementById('net-view-topo').classList.toggle('active', v === 'topology');
        document.getElementById('network-table-view').classList.toggle('hidden', v !== 'table');
        document.getElementById('network-topology-view').classList.toggle('hidden', v !== 'topology');
        if (v === 'topology') this.renderTopology();
    },

    activate() {
        App.startPolling('network', () => this.refresh(), 30000);
    },

    deactivate() {
        App.stopPolling('network');
        this.closeDetail();
    },

    async refresh() {
        try {
            const data = await App.api('/netkb_data_json');
            this.hosts = data.hosts || [];
            this.renderTable();
            if (this.view === 'topology') this.renderTopology();
        } catch (e) { /* retry */ }
    },

    renderTable() {
        const container = document.getElementById('network-table-view');
        if (!this.hosts.length) {
            container.innerHTML = '<div class="empty-state">No hosts discovered yet. Run a network scan from the Dashboard or Attacks tab.</div>';
            return;
        }

        container.innerHTML = this.hosts.map((h, idx) => {
            const alive = h.alive === '1';
            const hasCreds = this.hostHasCreds(h);
            const statusCls = hasCreds ? 'pwned' : (alive ? 'alive' : 'dead');
            const ports = (h.ports || '').replace(/;/g, ', ') || 'none';
            const hostname = h.hostname || '-';
            const summary = this.getHostSummary(h);

            let actionsHtml = '';
            const actionKeys = Object.keys(h.actions || {});
            if (actionKeys.length) {
                const bruteForce = actionKeys.filter(k => k.includes('Bruteforce'));
                const steal = actionKeys.filter(k => k.includes('Steal'));
                if (bruteForce.length) {
                    actionsHtml += '<div class="host-detail-row"><span class="label">Brute Force</span><div>' +
                        bruteForce.map(k => this.renderActionBadge(k, h.actions[k])).join('') + '</div></div>';
                }
                if (steal.length) {
                    actionsHtml += '<div class="host-detail-row"><span class="label">Data Theft</span><div>' +
                        steal.map(k => this.renderActionBadge(k, h.actions[k])).join('') + '</div></div>';
                }
            }

            return `
                <div class="host-card" id="host-${idx}">
                    <div class="host-header" onclick="NetworkTab.toggleHost(${idx})">
                        <div class="host-status ${statusCls}"></div>
                        <span class="host-ip">${h.ip}</span>
                        <span class="host-name">${hostname}</span>
                        <span class="host-summary">${summary}</span>
                        <span class="host-toggle">&#9654;</span>
                    </div>
                    <div class="host-details">
                        <div class="host-detail-row"><span class="label">MAC</span><span>${h.mac || '-'}</span></div>
                        <div class="host-detail-row"><span class="label">Ports</span><span>${ports}</span></div>
                        <div class="host-detail-row"><span class="label">Alive</span><span class="${alive ? 'text-success' : 'text-danger'}">${alive ? 'Yes' : 'No'}</span></div>
                        ${actionsHtml}
                    </div>
                </div>
            `;
        }).join('');
    },

    toggleHost(idx) {
        const card = document.getElementById('host-' + idx);
        if (card) card.classList.toggle('expanded');
    },

    renderActionBadge(key, val) {
        const name = key.replace('Bruteforce', '').replace('StealFiles', '').replace('StealData', '');
        if (!val || !val.trim()) return '<span class="action-result pending">' + name + ': -</span>';
        const isSuccess = val.toLowerCase().includes('success');
        const cls = isSuccess ? 'success' : 'failed';
        const icon = isSuccess ? 'OK' : 'X';
        return '<span class="action-result ' + cls + '">' + name + ': ' + icon + '</span>';
    },

    hostHasCreds(host) {
        const actions = host.actions || {};
        return Object.keys(actions).some(k =>
            k.includes('Bruteforce') && (actions[k] || '').toLowerCase().includes('success')
        );
    },

    getHostSummary(host) {
        const actions = host.actions || {};
        let s = 0, f = 0;
        Object.values(actions).forEach(v => {
            if (v && v.toLowerCase().includes('success')) s++;
            else if (v && v.toLowerCase().includes('failed')) f++;
        });
        const parts = [];
        if (s) parts.push('<span class="text-success">' + s + ' ok</span>');
        if (f) parts.push('<span class="text-danger">' + f + ' fail</span>');
        const portCount = (host.ports || '').split(';').filter(p => p.trim()).length;
        if (portCount) parts.push(portCount + 'p');
        return parts.join(' ');
    },

    /* --- SVG Topology --- */
    renderTopology() {
        const svg = document.getElementById('topology-svg');
        if (!svg) return;
        const container = svg.parentElement;
        const w = container.clientWidth || 400;
        const h = Math.max(container.clientHeight, 400);
        svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
        svg.setAttribute('width', w);
        svg.setAttribute('height', h);
        svg.innerHTML = '';

        if (!this.hosts.length) {
            const t = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            t.setAttribute('x', w / 2);
            t.setAttribute('y', h / 2);
            t.setAttribute('text-anchor', 'middle');
            t.setAttribute('fill', '#6b6156');
            t.setAttribute('font-size', '14');
            t.textContent = 'No hosts to display';
            svg.appendChild(t);
            return;
        }

        const cx = w / 2;
        const cy = h / 2;
        const r = Math.min(w, h) / 2 - 60;

        // Calculate node positions
        const nodes = this.hosts.map((host, i) => {
            const angle = (2 * Math.PI * i) / this.hosts.length - Math.PI / 2;
            return {
                x: cx + r * Math.cos(angle),
                y: cy + r * Math.sin(angle),
                host: host,
                idx: i
            };
        });

        // Draw links from each node to center
        nodes.forEach(n => {
            const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
            line.setAttribute('x1', cx);
            line.setAttribute('y1', cy);
            line.setAttribute('x2', n.x);
            line.setAttribute('y2', n.y);
            line.setAttribute('class', 'topo-link');
            svg.appendChild(line);
        });

        // Draw center (gateway) node
        this.drawNode(svg, cx, cy, 'GW', '#5bc0de', 20);

        // Draw host nodes
        nodes.forEach(n => {
            const hasCreds = this.hostHasCreds(n.host);
            const alive = n.host.alive === '1';
            const color = hasCreds ? '#e99f00' : (alive ? '#4caf50' : '#d9534f');
            const label = n.host.ip.split('.').pop();
            const g = this.drawNode(svg, n.x, n.y, label, color, 16);
            g.style.cursor = 'pointer';
            g.addEventListener('click', e => {
                e.stopPropagation();
                this.showDetail(n.host, n.x, n.y);
            });
        });
    },

    drawNode(svg, x, y, label, color, radius) {
        const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
        g.setAttribute('class', 'topo-node');
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', x);
        circle.setAttribute('cy', y);
        circle.setAttribute('r', radius);
        circle.setAttribute('fill', color);
        circle.setAttribute('stroke', color);
        circle.setAttribute('fill-opacity', '0.2');
        g.appendChild(circle);

        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', x);
        text.setAttribute('y', y + 4);
        text.textContent = label;
        g.appendChild(text);

        svg.appendChild(g);
        return g;
    },

    showDetail(host, x, y) {
        this.closeDetail();
        const container = document.getElementById('network-topology-view');
        const div = document.createElement('div');
        div.className = 'topo-detail';
        div.style.left = Math.min(x, container.clientWidth - 250) + 'px';
        div.style.top = Math.min(y + 30, container.clientHeight - 150) + 'px';

        const ports = (host.ports || '').replace(/;/g, ', ') || 'none';
        div.innerHTML =
            '<span class="close-detail" onclick="NetworkTab.closeDetail()">x</span>' +
            '<div><strong>' + host.ip + '</strong></div>' +
            '<div class="text-muted">' + (host.hostname || 'Unknown') + '</div>' +
            '<div class="mt-8">MAC: ' + (host.mac || '-') + '</div>' +
            '<div>Ports: ' + ports + '</div>' +
            '<div>Alive: ' + (host.alive === '1' ? '<span class="text-success">Yes</span>' : '<span class="text-danger">No</span>') + '</div>';
        container.appendChild(div);
        this.detailEl = div;
    },

    closeDetail() {
        if (this.detailEl) {
            this.detailEl.remove();
            this.detailEl = null;
        }
    }
};

App.registerTab('network', NetworkTab);
