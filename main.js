// FireShark Main JavaScript
// All logic from upload.html <script> goes here

// DOM elements
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const loading = document.getElementById('loading');
const result = document.getElementById('result');
const uploadBtn = document.getElementById('uploadBtn');

// Upload button handler
if (uploadBtn) {
    uploadBtn.addEventListener('click', () => {
        fileInput.click();
    });
}

// API base URL - change this if your FastAPI server runs on a different port
const API_BASE = 'http://localhost:8000';

// Drag and drop handlers
if (uploadArea) {
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('dragover');
    });
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('dragover');
    });
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('dragover');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFile(files[0]);
        }
    });
}

// File input handler
if (fileInput) {
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFile(e.target.files[0]);
        }
    });
}

async function handleFile(file) {
    // Validate file type
    const allowedTypes = ['.pcap', '.cap', '.pcapng'];
    const fileName = file.name.toLowerCase();
    const isValidType = allowedTypes.some(ext => fileName.endsWith(ext));
    if (!isValidType) {
        showResult('error', 'Invalid file type. Please upload a .pcap, .cap, or .pcapng file.');
        return;
    }
    // Validate file size (50MB limit)
    if (file.size > 50 * 1024 * 1024) {
        showResult('error', 'File too large. Maximum size is 50MB.');
        return;
    }
    // Show loading
    loading.style.display = 'block';
    result.style.display = 'none';
    try {
        const formData = new FormData();
        formData.append('file', file);
        const response = await fetch(`${API_BASE}/upload`, {
            method: 'POST',
            body: formData
        });
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || `HTTP ${response.status}`);
        }
        const analysisResult = await response.json();
        showResult('success', 'Analysis Complete!', analysisResult);
    } catch (error) {
        console.error('Upload error:', error);
        if (error.message.includes('Failed to fetch')) {
            showResult('error',
                'Cannot connect to FireShark API. Make sure the server is running on http://localhost:8000\n\n' +
                'To start the server, run:\nuvicorn app.app:app --reload --host 0.0.0.0 --port 8000'
            );
        } else {
            showResult('error', `Upload failed: ${error.message}`);
        }
    } finally {
        loading.style.display = 'none';
    }
}

function showResult(type, message, data = null) {
    result.className = `result ${type}`;
    let content = `<strong>${message}</strong>`;
    if (data && data.scans && data.scans.length > 0) {
        content += `<br><br><span style='color:#ff6a00;'>Detected Scans:</span>`;
        document.getElementById('showAllBtn').style.display = 'inline-block';
        document.getElementById('showRawBtn').style.display = 'inline-block';
    } else {
        document.getElementById('showAllBtn').style.display = 'none';
        document.getElementById('showRawBtn').style.display = 'none';
    }
    result.innerHTML = content;
    result.style.display = 'block';
    showScanSummary(data && data.scans ? data.scans : []);
    showScanResults(data && data.scans ? data.scans : []);
    hideRawJson();
}
function showScanSummary(scans) {
    const scanSummary = document.getElementById('scanSummary');
    if (!scans || scans.length === 0) {
        scanSummary.innerHTML = '';
        return;
    }
    // Group by src/dst
    const srcGroups = {};
    scans.forEach(scan => {
        const key = `${scan.src}→${scan.unique_dsts.join(',')}`;
        if (!srcGroups[key]) srcGroups[key] = [];
        srcGroups[key].push(scan);
    });
    let summaryHtml = `<div><span class='icon'>🛡️</span> <strong>Total Scans:</strong> ${scans.length}</div>`;
    summaryHtml += `<div><span class='icon'>⚡</span> <strong>Sources:</strong> ${[...new Set(scans.map(s=>s.src))].join(', ')}</div>`;
    summaryHtml += `<div><span class='icon'>🎯</span> <strong>Destinations:</strong> ${[...new Set(scans.flatMap(s=>s.unique_dsts))].join(', ')}</div>`;
    summaryHtml += `<div><span class='icon'>🔢</span> <strong>Busiest Port:</strong> ${findBusiestPort(scans)}</div>`;
    scanSummary.innerHTML = summaryHtml;
}
function findBusiestPort(scans) {
    const portCounts = {};
    scans.forEach(scan => {
        if (scan.unique_ports) {
            scan.unique_ports.forEach(port => {
                portCounts[port] = (portCounts[port] || 0) + 1;
            });
        }
    });
    const sorted = Object.entries(portCounts).sort((a,b)=>b[1]-a[1]);
    return sorted.length ? sorted[0][0] : 'N/A';
}
function showScanResults(scans) {
    if (!scans || scans.length === 0) {
        document.getElementById('scanResults').innerHTML = '';
        return;
    }
    if (!window._lastScans || window._lastScans.length !== scans.length) {
        window._lastScans = scans.map(s => ({...s, _expanded: false}));
    }
    const scanResults = document.getElementById('scanResults');
    scanResults.innerHTML = window._lastScans.map((scan, idx) => `
        <div class='scan-card' id='scanCard${idx}'>
            <div class='scan-header'>
                <span class='icon'>🚨</span> ${scan.type} Detected
                <span class='scan-toggle' onclick='toggleScanDetails(${idx})'>[${scan._expanded ? "Hide" : "Show"} Details]</span>
            </div>
            <div class='timeline-bar'>${renderTimelineBar(scan.start_time, scan.end_time)}</div>
            <div class='timeline-label'>Scan Window: ${formatTime(scan.start_time)} - ${formatTime(scan.end_time)}</div>
            <table class='scan-table' style='display:${scan._expanded ? "table" : "none"};'>
                <tr><th>Source</th><td>${scan.src}</td></tr>
                <tr><th>Destination(s)</th><td>${scan.unique_dsts.join(', ')}</td></tr>
                <tr><th>Start Time</th><td>${formatTime(scan.start_time)}</td></tr>
                <tr><th>End Time</th><td>${formatTime(scan.end_time)}</td></tr>
                <tr><th>Ports Scanned</th><td class='scan-ports'>${renderPortTags(scan.unique_ports)}</td></tr>
                <tr><th>Count</th><td>${scan.count}</td></tr>
            </table>
        </div>
    `).join('');
}
function showAllDetails() {
    if (!window._lastScans) return;
    window._lastScans.forEach(s => s._expanded = true);
    showScanResults(window._lastScans);
}
function toggleRawJson() {
    const rawJson = document.getElementById('rawJson');
    if (rawJson.style.display === 'block') {
        hideRawJson();
    } else {
        showRawJson(window._lastScans);
    }
}
function showRawJson(scans) {
    const rawJson = document.getElementById('rawJson');
    if (!scans || scans.length === 0) {
        rawJson.style.display = 'none';
        rawJson.innerHTML = '';
        return;
    }
    rawJson.style.display = 'block';
    rawJson.innerHTML = `<pre>${JSON.stringify(scans, null, 2)}</pre>`;
}
function hideRawJson() {
    const rawJson = document.getElementById('rawJson');
    rawJson.style.display = 'none';
    rawJson.innerHTML = '';
}
function renderPortTags(ports) {
    if (!ports || ports.length === 0) return '';
    const wellKnown = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5900,8080];
    const portNames = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'MS RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC', 8080: 'HTTP-alt'
    };
    return ports.sort((a,b)=>a-b).map(port => {
        const isWellKnown = wellKnown.includes(port);
        const name = portNames[port] ? ` (${portNames[port]})` : '';
        return `<span class='port-tag${isWellKnown ? ' well-known' : ''}' title='Port ${port}${name}'>${port}${name}</span>`;
    }).join('');
}
function renderTimelineBar(start, end) {
    // Show scan window as a marker on a 60s bar
    const min = start;
    const max = start + 60;
    const percentStart = 0;
    const percentEnd = Math.min(100, ((end-min)/60)*100);
    return `<div class='timeline-bar'><div class='timeline-marker' style='left:${percentEnd}%;'></div></div>`;
}
function formatTime(ts) {
    if (!ts) return '';
    const d = new Date(ts*1000);
    return d.toLocaleString();
}
// Test API connection on page load
async function testConnection() {
    try {
        const response = await fetch(`${API_BASE}/ping`);
        if (response.ok) {
            console.log('✅ API connection successful');
        } else {
            console.warn('⚠️ API responded with error:', response.status);
        }
    } catch (error) {
        console.warn('⚠️ Cannot connect to API:', error.message);
    }
}
testConnection();
