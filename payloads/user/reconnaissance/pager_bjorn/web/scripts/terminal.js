/* ========================================
   Terminal Tab - Web Command Execution
   ======================================== */
'use strict';

var TerminalTab = {
    history: [],
    historyIndex: -1,
    output: null,
    input: null,

    init() {
        var panel = document.getElementById('tab-terminal');
        panel.innerHTML = '<div class="terminal-panel">' +
            '<div class="terminal-output" id="term-output">' +
            '<div class="text-muted">Bjorn Terminal - Commands execute on the device.</div>' +
            '<div class="text-muted mb-8">Working directory: /mmc/root/loot/bjorn</div>' +
            '</div>' +
            '<div class="terminal-input-row">' +
            '<span class="terminal-prompt">$</span>' +
            '<input class="terminal-input" id="term-input" type="text" placeholder="Enter command..." autocomplete="off" spellcheck="false">' +
            '<button class="btn btn-gold btn-sm" id="term-send">Run</button>' +
            '</div></div>';

        this.output = document.getElementById('term-output');
        this.input = document.getElementById('term-input');

        // Load history from sessionStorage
        try {
            this.history = JSON.parse(sessionStorage.getItem('bjorn_term_history') || '[]');
        } catch (e) { this.history = []; }

        this.input.addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                this.execute();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.navigateHistory(-1);
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.navigateHistory(1);
            }
        });

        document.getElementById('term-send').addEventListener('click', () => this.execute());
    },

    activate() {
        setTimeout(() => this.input.focus(), 100);
    },

    deactivate() {},

    async execute() {
        var cmd = this.input.value.trim();
        if (!cmd) return;

        // Add to history
        if (!this.history.length || this.history[this.history.length - 1] !== cmd) {
            this.history.push(cmd);
            if (this.history.length > 100) this.history.shift();
            sessionStorage.setItem('bjorn_term_history', JSON.stringify(this.history));
        }
        this.historyIndex = -1;
        this.input.value = '';

        // Show command in output
        var cmdDiv = document.createElement('div');
        cmdDiv.className = 'terminal-cmd';
        cmdDiv.textContent = cmd;
        this.output.appendChild(cmdDiv);

        // Disable input while running
        this.input.disabled = true;

        try {
            var result = await App.post('/api/terminal', { command: cmd });
            var resDiv = document.createElement('div');
            resDiv.className = 'terminal-result' + (result.exit_code !== 0 ? ' error' : '');
            resDiv.textContent = result.output || '(no output)';
            if (result.exit_code !== 0) {
                resDiv.textContent += '\n[exit code: ' + result.exit_code + ']';
            }
            this.output.appendChild(resDiv);
        } catch (e) {
            var errDiv = document.createElement('div');
            errDiv.className = 'terminal-result error';
            errDiv.textContent = 'Error: ' + e.message;
            this.output.appendChild(errDiv);
        }

        this.input.disabled = false;
        this.input.focus();
        this.output.scrollTop = this.output.scrollHeight;
    },

    navigateHistory(dir) {
        if (!this.history.length) return;
        if (this.historyIndex === -1) {
            if (dir === -1) this.historyIndex = this.history.length - 1;
            else return;
        } else {
            this.historyIndex += dir;
        }

        if (this.historyIndex < 0) this.historyIndex = 0;
        if (this.historyIndex >= this.history.length) {
            this.historyIndex = -1;
            this.input.value = '';
            return;
        }

        this.input.value = this.history[this.historyIndex];
    }
};

App.registerTab('terminal', TerminalTab);
