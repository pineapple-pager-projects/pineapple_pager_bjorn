const logConsole = document.getElementById('log-console');
const mainToolbar = document.querySelector('.toolbar');
const toggleButton = document.getElementById('toggle-toolbar');
let fontSize = 16; // size for desktop
const maxLines = 2000; // Number of lines to keep in the console
const fileColors = new Map();
const levelClasses = {
    "DEBUG": "debug",
    "INFO": "info",
    "WARNING": "warning",
    "ERROR": "error",
    "CRITICAL": "critical",
    "SUCCESS": "success"
};

// Adjust font size based on device type
if (/Mobi|Android/i.test(navigator.userAgent)) {
    fontSize = 7; // size for mobile
}
logConsole.style.fontSize = fontSize + 'px';

function getRandomColor() {
    const letters = '89ABCDEF';  // Using only hex value for lighter colors
    let color = '#';
    for (let i = 0; i < 6; i++) {
        color += letters[Math.floor(Math.random() * letters.length)];
    }
    return color;
}

let logInterval;
let isConsoleOn = false;
// Use window.manualModeActive so inline scripts can control it
window.manualModeActive = false;

// Track last log timestamp for incremental fetching
let lastLogTimestamp = null;

// Track user interaction with log console to pause updates during selection
let isSelecting = false;
let lastInteractionTime = 0;
const INTERACTION_PAUSE_MS = 3000; // Pause updates for 3 seconds after interaction

// Detect when user starts selecting text
logConsole.addEventListener('mousedown', () => {
    isSelecting = true;
    lastInteractionTime = Date.now();
});

// Detect when user finishes selecting
document.addEventListener('mouseup', () => {
    isSelecting = false;
    // If there's a selection, update the interaction time to keep pausing
    const selection = window.getSelection();
    if (selection && selection.toString().length > 0) {
        lastInteractionTime = Date.now();
    }
});

// Also handle touch events for mobile
logConsole.addEventListener('touchstart', () => {
    isSelecting = true;
    lastInteractionTime = Date.now();
});

document.addEventListener('touchend', () => {
    isSelecting = false;
    const selection = window.getSelection();
    if (selection && selection.toString().length > 0) {
        lastInteractionTime = Date.now();
    }
});

function shouldPauseUpdates() {
    // Pause if user is actively selecting
    if (isSelecting) return true;

    // Pause if user has text selected
    const selection = window.getSelection();
    if (selection && selection.toString().length > 0) return true;

    // Pause for a few seconds after any interaction
    if (Date.now() - lastInteractionTime < INTERACTION_PAUSE_MS) return true;

    return false;
}

function fetchLogs() {
    // Don't update if in manual mode
    if (window.manualModeActive) {
        return;
    }

    // Don't update if user is interacting with the log
    if (shouldPauseUpdates()) {
        return;
    }

    // Build URL with since parameter for incremental fetching
    let url = '/get_logs';
    if (lastLogTimestamp) {
        url += '?since=' + encodeURIComponent(lastLogTimestamp);
    }

    fetch(url)
        .then(response => response.text())
        .then(data => {
            // Double-check before updating DOM
            if (window.manualModeActive || shouldPauseUpdates()) {
                return;
            }

            // Skip if no new data
            if (!data || data.trim() === '' || data.startsWith('Waiting for') || data.startsWith('No log entries')) {
                return;
            }

            const lines = data.split('\n');
            const newContent = [];

            // Regex to extract timestamp from log line (with optional milliseconds)
            const timestampRegex = /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d{3})?)/;

            lines.forEach(line => {
                if (!line.trim()) return;

                // Extract timestamp and update lastLogTimestamp
                const tsMatch = line.match(timestampRegex);
                if (tsMatch) {
                    lastLogTimestamp = tsMatch[1];
                }

                let modifiedLine = line;
                const regexFile = /(\w+\.py)/g;
                let matchFile;
                while ((matchFile = regexFile.exec(line)) !== null) {
                    const fileName = matchFile[1];
                    if (line.includes('==>') || line.includes('<=='))
                    return;
                    if (!fileColors.has(fileName)) {
                        fileColors.set(fileName, getRandomColor());
                    }
                    modifiedLine = modifiedLine.replace(fileName, `<span style="color: ${fileColors.get(fileName)};">${fileName}</span>`);
                }

                const regexLevel = /\b(DEBUG|INFO|WARNING|ERROR|CRITICAL|SUCCESS)\b/g;
                modifiedLine = modifiedLine.replace(regexLevel, (match) => {
                    return `<span class="${levelClasses[match]}">${match}</span>`;
                });

                const regexLineNumber = /^\d+/;
                modifiedLine = modifiedLine.replace(regexLineNumber, (match) => {
                    return `<span class="line-number">${match}</span>`;
                });

                const regexNumbers = /\b\d+\b/g;
                modifiedLine = modifiedLine.replace(regexNumbers, (match) => {
                    return `<span class="number">${match}</span>`;
                });

                newContent.push(modifiedLine);
            });

            // Final check right before updating DOM
            if (shouldPauseUpdates() || newContent.length === 0) {
                return;
            }

            // Append new content
            if (logConsole.innerHTML) {
                logConsole.innerHTML += '<br>' + newContent.join('<br>');
            } else {
                logConsole.innerHTML = newContent.join('<br>');
            }

            // Trim old lines if over maxLines
            let allLines = logConsole.innerHTML.split('<br>');
            if (allLines.length > maxLines) {
                allLines = allLines.slice(allLines.length - maxLines);
                logConsole.innerHTML = allLines.join('<br>');
            }
            // No auto-scroll - let user scroll freely
        })
        .catch(error => console.error('Error fetching logs:', error));
}

// setInterval(fetchLogs, 1500); /
function startConsole() {
    // Start fetching logs every 1.5 seconds
    logInterval = setInterval(fetchLogs, 1500); // Fetch logs every 1.5 seconds
}
function stopConsole() {
    clearInterval(logInterval);
}
function toggleConsole() {
    const toggleImage = document.getElementById('toggle-console-image');
    
    if (isConsoleOn) {
        stopConsole();
        toggleImage.src = '/web/images/off.png';
    } else {
        startConsole();
        toggleImage.src = '/web/images/on.png';
    }
    
    isConsoleOn = !isConsoleOn;
}
function adjustFontSize(change) {
    fontSize += change;
    logConsole.style.fontSize = fontSize + 'px';
}

document.addEventListener('DOMContentLoaded', () => {
    const mainToolbar = document.getElementById('mainToolbar');
    const toggleButton = document.getElementById('toggle-toolbar');
    const toggleIcon = document.getElementById('toggle-icon');

    toggleButton.addEventListener('click', toggleToolbar);

    function toggleToolbar() {
        const isOpen = toggleButton.getAttribute('data-open') === 'true';
        if (isOpen) {
            mainToolbar.classList.add('hidden');
            toggleIcon.src = '/web/images/reveal.png';
            toggleButton.setAttribute('data-open', 'false');
        } else {
            mainToolbar.classList.remove('hidden');
            toggleIcon.src = '/web/images/hide.png';
            toggleButton.setAttribute('data-open', 'true');
        }
        toggleConsoleSize();
    }

    function toggleConsoleSize() {
        //Function to adjust the size of the console based on the toolbar visibility
    }
});

function clear_files() {
    fetch('/clear_files', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message))
        .catch(error => alert('Failed to clear files: ' + error.message));
}

function clear_files_light() {
    fetch('/clear_files_light', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message))
        .catch(error => alert('Failed to clear files: ' + error.message));
}

function reboot_system() {
    fetch('/reboot', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message))
        .catch(error => alert('Failed to reboot: ' + error.message));
}

function shutdown_system() {
    fetch('/shutdown', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message))
        .catch(error => alert('Failed to shutdown: ' + error.message));
}

function restart_bjorn_service() {
    fetch('/restart_bjorn_service', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message))
        .catch(error => alert('Failed to restart service: ' + error.message));
}

function backup_data() {
    fetch('/backup', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                const link = document.createElement('a');
                link.href = data.url;
                link.download = data.filename;
                link.click();
                alert('Backup completed successfully');
            } else {
                alert('Backup failed: ' + data.message);
            }
        })
        .catch(error => alert('Backup failed: ' + error.message));
}

function restore_data() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.zip';
    input.onchange = () => {
        const file = input.files[0];
        const formData = new FormData();
        formData.append('file', file);

        fetch('/restore', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => alert(data.message))
        .catch(error => alert('Restore failed: ' + error.message));
    };
    input.click();
}

function stop_orchestrator() {
    fetch('/stop_orchestrator', { method: 'POST' })
        .then(response => response.json())
        .then(data => console.log('Orchestrator:', data.message))
        .catch(error => console.error('Failed to stop orchestrator:', error.message));
}

function start_orchestrator() {
    fetch('/start_orchestrator', { method: 'POST' })
        .then(response => response.json())
        .then(data => console.log('Orchestrator:', data.message))
        .catch(error => console.error('Failed to start orchestrator:', error.message));
}

function disconnect_wifi() {
    fetch('/disconnect_wifi', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message))
        .catch(error => alert('Failed to disconnect: ' + error.message));
}

function initialize_csv() {
    fetch('/initialize_csv', { method: 'POST' })
        .then(response => response.json())
        .then(data => alert(data.message))
        .catch(error => alert('Failed to initialize CSV: ' + error.message));
}

// Dropdown toggle logic
function toggleDropdown() {
    const dropdown = document.querySelector('.dropdown');
    const button = document.querySelector('.action-button');
    const isOpen = button.getAttribute('data-open') === 'true';

    if (isOpen) {
        dropdown.classList.remove('show');
        button.setAttribute('data-open', 'false');
    } else {
        dropdown.classList.add('show');
        button.setAttribute('data-open', 'true');
    }
}

function closeDropdownIfOpen(event) {
    const dropdown = document.querySelector('.dropdown');
    const button = document.querySelector('.action-button');
    const isOpen = button.getAttribute('data-open') === 'true';

    if (!event.target.closest('.dropdown') && isOpen) {
        dropdown.classList.remove('show');
        button.setAttribute('data-open', 'false');
    }
}

// actions.js

// Existing logic for Actions dropdown
function toggleDropdown() {
    const dropdown = document.querySelector('.dropdown');
    const button = document.querySelector('.action-button');
    const isOpen = button.getAttribute('data-open') === 'true';

    if (isOpen) {
        dropdown.classList.remove('show');
        button.setAttribute('data-open', 'false');
    } else {
        dropdown.classList.add('show');
        button.setAttribute('data-open', 'true');
    }
}

function closeDropdownIfOpen(event) {
    const dropdown = document.querySelector('.dropdown');
    const button = document.querySelector('.action-button');
    const isOpen = button.getAttribute('data-open') === 'true';

    if (!event.target.closest('.dropdown') && isOpen) {
        dropdown.classList.remove('show');
        button.setAttribute('data-open', 'false');
    }
}

