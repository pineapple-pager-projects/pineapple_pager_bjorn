/* ========================================
   Config Tab - Settings with Collapsible Sections
   ======================================== */
'use strict';

const ConfigTab = {
    config: null,

    init() {
        const panel = document.getElementById('tab-config');
        panel.innerHTML = `
            <div class="config-panel">
                <div class="config-header">
                    <button class="btn btn-gold" id="cfg-save">Save Config</button>
                    <button class="btn" id="cfg-restore">Restore Defaults</button>
                </div>
                <div class="config-body" id="config-body">
                    <div class="empty-state">Loading configuration...</div>
                </div>
            </div>
        `;

        document.getElementById('cfg-save').addEventListener('click', () => this.save());
        document.getElementById('cfg-restore').addEventListener('click', () => this.restore());
    },

    activate() {
        this.loadConfig();
    },

    deactivate() {},

    async loadConfig() {
        try {
            this.config = await App.api('/load_config');
            this.render();
        } catch (e) {
            document.getElementById('config-body').innerHTML = '<div class="empty-state">Error loading config.</div>';
        }
    },

    render() {
        if (!this.config) return;
        const body = document.getElementById('config-body');

        // Group keys by section titles (__title_*)
        const sections = [];
        var currentSection = { title: 'General', keys: [] };
        sections.push(currentSection);

        const keys = Object.keys(this.config);
        keys.forEach(key => {
            if (key.startsWith('__title_')) {
                currentSection = { title: this.config[key], keys: [] };
                sections.push(currentSection);
            } else if (!key.startsWith('__')) {
                currentSection.keys.push(key);
            }
        });

        body.innerHTML = sections.filter(s => s.keys.length).map((section, idx) => {
            const fields = section.keys.map(key => this.renderField(key, this.config[key])).join('');
            return '<div class="config-section expanded" id="cfg-section-' + idx + '">' +
                '<div class="config-section-header" onclick="ConfigTab.toggleSection(' + idx + ')">' +
                '<span>' + section.title + '</span>' +
                '<span class="collapse-icon">&#9654;</span>' +
                '</div>' +
                '<div class="config-section-body"><div class="config-grid">' + fields + '</div></div>' +
                '</div>';
        }).join('');
    },

    renderField(key, value) {
        var id = 'cfg-' + key;

        if (typeof value === 'boolean') {
            return '<div class="form-group">' +
                '<label class="toggle-wrap">' +
                '<div class="toggle">' +
                '<input type="checkbox" id="' + id + '" data-key="' + key + '" ' + (value ? 'checked' : '') + '>' +
                '<span class="toggle-slider"></span>' +
                '</div>' +
                '<span>' + key + '</span>' +
                '</label></div>';
        }

        if (Array.isArray(value)) {
            return '<div class="form-group">' +
                '<label class="form-label" for="' + id + '">' + key + '</label>' +
                '<input class="form-input" id="' + id + '" data-key="' + key + '" data-type="array" ' +
                'value="' + value.join(', ') + '" placeholder="comma-separated values">' +
                '</div>';
        }

        if (typeof value === 'number') {
            var isFloat = !Number.isInteger(value);
            return '<div class="form-group">' +
                '<label class="form-label" for="' + id + '">' + key + '</label>' +
                '<input class="form-input" type="number" id="' + id + '" data-key="' + key + '" data-type="number" ' +
                'value="' + value + '" step="' + (isFloat ? '0.1' : '1') + '">' +
                '</div>';
        }

        // String
        return '<div class="form-group">' +
            '<label class="form-label" for="' + id + '">' + key + '</label>' +
            '<input class="form-input" type="text" id="' + id + '" data-key="' + key + '" data-type="string" ' +
            'value="' + String(value).replace(/"/g, '&quot;') + '">' +
            '</div>';
    },

    toggleSection(idx) {
        var el = document.getElementById('cfg-section-' + idx);
        if (el) el.classList.toggle('expanded');
    },

    async save() {
        var data = {};
        document.querySelectorAll('#config-body [data-key]').forEach(el => {
            var key = el.dataset.key;
            var type = el.dataset.type;

            if (el.type === 'checkbox') {
                data[key] = el.checked;
            } else if (type === 'array') {
                data[key] = el.value.split(',').map(s => s.trim()).filter(s => s);
            } else if (type === 'number') {
                var v = el.value;
                data[key] = v.includes('.') ? parseFloat(v) : parseInt(v, 10);
            } else {
                var v = el.value;
                if (v.match(/^\d+$/)) data[key] = parseInt(v, 10);
                else if (v.match(/^\d+\.\d+$/)) data[key] = parseFloat(v);
                else data[key] = v;
            }
        });

        try {
            await App.post('/save_config', data);
            App.toast('Configuration saved', 'success');
        } catch (e) {
            App.toast('Save failed: ' + e.message, 'error');
        }
    },

    async restore() {
        if (!await App.confirm('Restore all settings to defaults?')) return;
        try {
            this.config = await App.api('/restore_default_config');
            this.render();
            App.toast('Defaults restored', 'success');
        } catch (e) {
            App.toast('Failed: ' + e.message, 'error');
        }
    }
};

App.registerTab('config', ConfigTab);
