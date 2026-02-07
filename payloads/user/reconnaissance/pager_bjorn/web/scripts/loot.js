let fontSize = 14;
// Adjust font size based on device type
if (/Mobi|Android/i.test(navigator.userAgent)) {
    fontSize = 7; // size for mobile
}

// Track expanded sections to preserve state during updates
let expandedSections = new Set();

function saveExpandedState() {
    // Find all expanded sections and save their IDs
    document.querySelectorAll('.tree-content').forEach(el => {
        if (el.style.display !== 'none') {
            expandedSections.add(el.id);
        }
    });
}

function restoreExpandedState() {
    // Restore expanded state for all saved sections
    expandedSections.forEach(id => {
        const content = document.getElementById(id);
        const iconId = id.replace('content-', 'icon-');
        const icon = document.getElementById(iconId);
        if (content) {
            content.style.display = 'block';
            if (icon) icon.textContent = '▼';
        }
    });
}

function fetchFiles() {
    saveExpandedState();
    fetch('/list_files')
        .then(response => response.json())
        .then(data => {
            document.getElementById('file-list').innerHTML = generateFileTreeHTML(data, "/", 0);
            restoreExpandedState();
        })
        .catch(error => {
            console.error('Error fetching files:', error);
        });
}

function fetchLogs() {
    saveExpandedState();
    fetch('/list_logs')
        .then(response => response.json())
        .then(data => {
            document.getElementById('log-list').innerHTML = generateLogTreeHTML(data);
            restoreExpandedState();
        })
        .catch(error => {
            console.error('Error fetching logs:', error);
        });
}

function toggleSection(sectionId) {
    const content = document.getElementById('content-' + sectionId);
    const icon = document.getElementById('icon-' + sectionId);
    if (content.style.display === 'none') {
        content.style.display = 'block';
        icon.textContent = '▼';
        expandedSections.add('content-' + sectionId);
    } else {
        content.style.display = 'none';
        icon.textContent = '▶';
        expandedSections.delete('content-' + sectionId);
    }
}

function generateLogTreeHTML(data) {
    if (!data || (!data.categories.length && !data.uncategorized.length)) {
        return '<p style="color: #888;">No log files found.</p>';
    }

    let html = '<ul class="loot-tree">';

    // Render categories
    data.categories.forEach((cat, idx) => {
        const catId = 'log-' + cat.id;
        html += `
            <li class="tree-node">
                <div class="tree-header" onclick="toggleSection('${catId}')">
                    <span id="icon-${catId}" class="tree-icon">▶</span>
                    <img src="web/images/subfolder.png" alt="Category" style="height: 18px; margin-right: 5px;">
                    <strong>${cat.label}</strong>
                    <span class="tree-count">(${cat.logs.length})</span>
                </div>
                <div id="content-${catId}" class="tree-content" style="display: none;">
                    <ul>`;
        cat.logs.forEach(log => {
            html += `
                        <li class="tree-file">
                            <img src="web/images/file.png" alt="Log" style="height: 16px;">
                            <a href="/download_log?name=${encodeURIComponent(log.name)}">${log.name}</a>
                            <span class="file-size">(${log.size})</span>
                        </li>`;
        });
        html += `
                    </ul>
                </div>
            </li>`;
    });

    // Render uncategorized logs
    if (data.uncategorized && data.uncategorized.length > 0) {
        const catId = 'log-other';
        html += `
            <li class="tree-node">
                <div class="tree-header" onclick="toggleSection('${catId}')">
                    <span id="icon-${catId}" class="tree-icon">▶</span>
                    <img src="web/images/subfolder.png" alt="Category" style="height: 18px; margin-right: 5px;">
                    <strong>Other Logs</strong>
                    <span class="tree-count">(${data.uncategorized.length})</span>
                </div>
                <div id="content-${catId}" class="tree-content" style="display: none;">
                    <ul>`;
        data.uncategorized.forEach(log => {
            html += `
                        <li class="tree-file">
                            <img src="web/images/file.png" alt="Log" style="height: 16px;">
                            <a href="/download_log?name=${encodeURIComponent(log.name)}">${log.name}</a>
                            <span class="file-size">(${log.size})</span>
                        </li>`;
        });
        html += `
                    </ul>
                </div>
            </li>`;
    }

    html += '</ul>';
    return html;
}

function generateFileTreeHTML(files, path, indent) {
    if (!files || files.length === 0) {
        if (indent === 0) {
            return '<p style="color: #888;">No stolen data found.</p>';
        }
        return '';
    }

    let html = '<ul class="loot-tree">';
    files.forEach((file, idx) => {
        if (file.is_directory) {
            const nodeId = 'file-' + path.replace(/[^a-zA-Z0-9]/g, '-') + '-' + idx;
            const icon = path === "/" ? "web/images/mainfolder.png" : "web/images/subfolder.png";
            const childCount = file.children ? file.children.length : 0;
            html += `
                <li class="tree-node" style="margin-left: ${indent * 10}px;">
                    <div class="tree-header" onclick="toggleSection('${nodeId}')">
                        <span id="icon-${nodeId}" class="tree-icon">▶</span>
                        <img src="${icon}" alt="Folder" style="height: 18px; margin-right: 5px;">
                        <strong>${file.name}</strong>
                        <span class="tree-count">(${childCount})</span>
                    </div>
                    <div id="content-${nodeId}" class="tree-content" style="display: none;">
                        ${generateFileTreeHTML(file.children || [], path + '/' + file.name, indent + 1)}
                    </div>
                </li>`;
        } else {
            html += `
                <li class="tree-file" style="margin-left: ${indent * 10}px;">
                    <img src="web/images/file.png" alt="File" style="height: 16px;">
                    <a href="/download_file?path=${encodeURIComponent(file.path)}">${file.name}</a>
                </li>`;
        }
    });
    html += '</ul>';
    return html;
}

function adjustLootFontSize(change) {
    fontSize += change;
    document.getElementById('file-list').style.fontSize = fontSize + 'px';
    document.getElementById('log-list').style.fontSize = fontSize + 'px';
}

function toggleLootToolbar() {
    const mainToolbar = document.querySelector('.toolbar');
    const toggleButton = document.getElementById('toggle-toolbar');
    const toggleIcon = document.getElementById('toggle-icon');
    if (mainToolbar.classList.contains('hidden')) {
        mainToolbar.classList.remove('hidden');
        toggleIcon.src = '/web/images/hide.png';
        toggleButton.setAttribute('data-open', 'false');
    } else {
        mainToolbar.classList.add('hidden');
        toggleIcon.src = '/web/images/reveal.png';
        toggleButton.setAttribute('data-open', 'true');
    }
}

document.addEventListener("DOMContentLoaded", function() {
    fetchFiles();
    fetchLogs();

    // Refresh files and logs every 10 seconds
    setInterval(() => {
        fetchFiles();
        fetchLogs();
    }, 10000);
});
