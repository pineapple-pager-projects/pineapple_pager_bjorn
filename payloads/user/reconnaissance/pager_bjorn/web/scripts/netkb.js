let fontSize = 12;
        // Adjust font size based on device type
if (/Mobi|Android/i.test(navigator.userAgent)) {
    fontSize = 7; // size for mobile
}
function fetchNetkbData() {
    fetch('/netkb_data')
        .then(response => response.text())
        .then(data => {
            document.getElementById('netkb-table').innerHTML = data;
        })
        .catch(error => {
            console.error('Error:', error);
        });
}
function adjustNetkbFontSize(change) {
    fontSize += change;
    // Set on container
    document.getElementById('netkb-table').style.fontSize = fontSize + 'px';
    // Set on all nested tables and cells
    document.querySelectorAll('#netkb-table table').forEach(t => {
        t.style.fontSize = fontSize + 'px';
    });
    document.querySelectorAll('#netkb-table td, #netkb-table th').forEach(cell => {
        cell.style.fontSize = fontSize + 'px';
    });
}




function toggleNetkbToolbar() {
    const mainToolbar = document.querySelector('.toolbar');
    const toggleButton = document.getElementById('toggle-toolbar')
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

function toggleCard(cardId) {
    const details = document.getElementById('details-' + cardId);
    const icon = document.getElementById('icon-' + cardId);
    if (details.style.display === 'none') {
        details.style.display = 'table-row';
        icon.textContent = '▼';
    } else {
        details.style.display = 'none';
        icon.textContent = '▶';
    }
}

function expandAll() {
    document.querySelectorAll('.details').forEach(el => {
        el.style.display = 'table-row';
    });
    document.querySelectorAll('.toggle-icon').forEach(el => {
        el.textContent = '▼';
    });
}

function collapseAll() {
    document.querySelectorAll('.details').forEach(el => {
        el.style.display = 'none';
    });
    document.querySelectorAll('.toggle-icon').forEach(el => {
        el.textContent = '▶';
    });
}

document.addEventListener("DOMContentLoaded", function() {
    fetchNetkbData(); // Initial fetch
    setInterval(fetchNetkbData, 10000); // Refresh every 10 seconds
});


