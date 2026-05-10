'use strict';

// ─── Severity Map ─────────────────────────────────────────────────────────────
const SEVERITY_MAP = {
    sql_injection_indicator:         'critical',
    http_trace_enabled:              'critical',
    sensitive_file_exposed:          'critical',
    cors_wildcard_with_credentials:  'critical',
    cors_wildcard_origin:            'high',
    cors_credentials_allowed:        'high',
    dangerous_http_methods:          'high',
    missing_csp:                     'high',
    xss_reflection:                  'high',
    csrf_missing_token:              'high',
    missing_hsts:                    'medium',
    missing_x_frame_options:         'medium',
    missing_x_content_type:          'medium',
    cookie_missing_httponly:         'medium',
    cookie_missing_secure:           'medium',
    cookie_missing_samesite:         'medium',
    cookie_excessive_expiry:         'medium',
    session_cookie_persistent:       'medium',
    session_id_in_url:               'medium',
    session_id_in_links:             'medium',
    mixed_content:                   'medium',
    server_info_disclosure:          'info',
    html_comment_disclosure:         'info',
    deprecated_header:               'info',
    info_disclosure:                 'info',
};

const SEARCH_QUERIES = {
    sql_injection_indicator:         'SQL Injection vulnerability OWASP how to fix',
    http_trace_enabled:              'HTTP TRACE method Cross-Site Tracing XST vulnerability fix',
    sensitive_file_exposed:          'sensitive file exposure web security how to prevent',
    cors_wildcard_with_credentials:  'CORS wildcard with credentials vulnerability critical fix',
    cors_wildcard_origin:            'CORS Access-Control-Allow-Origin wildcard security risk',
    cors_credentials_allowed:        'CORS allow credentials security misconfiguration',
    dangerous_http_methods:          'dangerous HTTP methods PUT DELETE security vulnerability',
    missing_csp:                     'Content Security Policy CSP missing header fix OWASP',
    xss_reflection:                  'Reflected XSS cross-site scripting OWASP fix',
    csrf_missing_token:              'CSRF missing token cross-site request forgery fix OWASP',
    missing_hsts:                    'HTTP Strict Transport Security HSTS missing header fix',
    missing_x_frame_options:         'X-Frame-Options missing clickjacking attack prevention',
    missing_x_content_type:          'X-Content-Type-Options nosniff missing header security',
    cookie_missing_httponly:         'Cookie HttpOnly flag missing security fix',
    cookie_missing_secure:           'Cookie Secure flag missing HTTPS security',
    cookie_missing_samesite:         'Cookie SameSite attribute missing CSRF fix',
    cookie_excessive_expiry:         'Cookie excessive max-age expiry security risk',
    session_cookie_persistent:       'Session cookie persistent expiry security vulnerability',
    session_id_in_url:               'Session ID in URL security vulnerability fix',
    session_id_in_links:             'Session token exposed in page links security risk',
    mixed_content:                   'Mixed content HTTP resources HTTPS page security fix',
    server_info_disclosure:          'Server version disclosure information leakage fix',
    html_comment_disclosure:         'HTML comments sensitive information disclosure security',
    deprecated_header:               'Deprecated HTTP security header removal best practice',
    info_disclosure:                 'Information disclosure web security OWASP',
};

function getSeverity(type) { return SEVERITY_MAP[type] || 'info'; }
function buildSearchQuery(f) {
    return SEARCH_QUERIES[f.type] || `${f.type.replace(/_/g,' ')} web vulnerability`;
}

// ─── Local Storage History ────────────────────────────────────────────────────
const HISTORY_KEY = 'owasp_scanner_history';

function loadHistory() {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); }
    catch { return []; }
}

function saveHistory(entries) {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(entries));
}

function addToHistory(report) {
    if (report.error) return; // don't save failed scans
    const entries = loadHistory();
    const entry = {
        id: Date.now(),
        url: report.url,
        scanned_at: new Date().toISOString(),
        status_code: report.status_code,
        finding_count: report.findings.length,
        critical_high: report.findings.filter(f => {
            const s = getSeverity(f.type);
            return s === 'critical' || s === 'high';
        }).length,
        report: report
    };
    entries.unshift(entry); // newest first
    if (entries.length > 50) entries.splice(50); // cap at 50
    saveHistory(entries);
}

function deleteHistoryEntry(id) {
    const entries = loadHistory().filter(e => e.id !== id);
    saveHistory(entries);
}

// ─── DOM refs ─────────────────────────────────────────────────────────────────
const urlInput      = document.getElementById('target-url');
const scanBtn       = document.getElementById('scan-btn');
const btnLabel      = scanBtn.querySelector('.btn-label');
const btnSpinner    = scanBtn.querySelector('.btn-spinner');
const scanLog       = document.getElementById('scan-log');
const logText       = document.getElementById('log-text');
const engineStatus  = document.getElementById('engine-status');

const resultsSection = document.getElementById('results');
const statStatus    = document.getElementById('stat-status');
const statFindings  = document.getElementById('stat-findings');
const statCritical  = document.getElementById('stat-critical');
const statForms     = document.getElementById('stat-forms');
const vulnCount     = document.getElementById('vuln-count');

const findingsList  = document.getElementById('findings-list');
const formsList     = document.getElementById('forms-list');
const exportJsonBtn = document.getElementById('export-json');
const filterBtns    = document.querySelectorAll('.filter-btn');

const termTitle     = document.getElementById('term-title');

let currentReport = null;
let currentFilter = 'all';

// ─── Tab Switching ────────────────────────────────────────────────────────────
const TAB_TITLES = {
    scan:    'scan-target — zsh — 120×40',
    history: 'scan-history — zsh — 120×40',
    reports: 'report-generator — zsh — 120×40',
};

document.querySelectorAll('.nav-link[data-tab]').forEach(link => {
    link.addEventListener('click', e => {
        e.preventDefault();
        const tab = link.dataset.tab;

        document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
        link.classList.add('active');

        document.querySelectorAll('.tab-content').forEach(t => {
            t.classList.remove('active');
            t.classList.add('hidden');
        });

        const target = document.getElementById(`tab-${tab}`);
        target.classList.remove('hidden');
        target.classList.add('active');
        termTitle.textContent = TAB_TITLES[tab] || '';

        if (tab === 'history') renderHistory();
        if (tab === 'reports') renderReportTab();
    });
});

// ─── Scan UI State ────────────────────────────────────────────────────────────
function setScanning(on) {
    urlInput.disabled = on;
    scanBtn.disabled  = on;
    btnLabel.classList.toggle('hidden', on);
    btnSpinner.classList.toggle('hidden', !on);
    scanLog.classList.toggle('hidden', !on);
    engineStatus.textContent = on ? 'ENGINE RUNNING' : 'ENGINE IDLE';
    if (!on) scanLog.classList.add('hidden');
}

const LOG_MESSAGES = [
    'Resolving DNS...', 'Establishing connection...', 'Fetching target response...',
    'Parsing HTML structure...', 'Running security checks...',
    'Analyzing headers & cookies...', 'Probing sensitive paths...',
    'Checking HTTP methods...', 'Running plugin checks...', 'Compiling report...',
];
let logIdx = 0, logTimer = null;

function startLogCycle() {
    logIdx = 0; logText.textContent = LOG_MESSAGES[0]; clearInterval(logTimer);
    logTimer = setInterval(() => { logIdx = (logIdx + 1) % LOG_MESSAGES.length; logText.textContent = LOG_MESSAGES[logIdx]; }, 1800);
}
function stopLogCycle() { clearInterval(logTimer); }

// ─── Kick off scan ────────────────────────────────────────────────────────────
scanBtn.addEventListener('click', async () => {
    let url = urlInput.value.trim();
    if (!url) return;
    if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

    setScanning(true); startLogCycle();
    resultsSection.classList.add('hidden');
    currentReport = null; exportJsonBtn.disabled = true;

    try {
        const res  = await fetch('/api/scan', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url}) });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Unknown error');
        pollJob(data.job_id);
    } catch(err) {
        stopLogCycle(); setScanning(false);
        showError('Could not start scan: ' + err.message);
    }
});

async function pollJob(jobId) {
    try {
        const res  = await fetch(`/api/scan/${jobId}`);
        const data = await res.json();
        if (data.status === 'completed') {
            stopLogCycle(); setScanning(false);
            addToHistory(data.report);
            renderReport(data.report);
        } else if (data.status === 'failed') {
            stopLogCycle(); setScanning(false);
            showError('Scan failed: ' + (data.error || 'unknown'));
        } else {
            setTimeout(() => pollJob(jobId), 1000);
        }
    } catch(err) {
        stopLogCycle(); setScanning(false);
        showError('Polling error: ' + err.message);
    }
}

// ─── Render Scan Results ──────────────────────────────────────────────────────
function renderReport(report, switchTab = false) {
    currentReport = { ...report, scanned_at: report.scanned_at || new Date().toISOString() };
    resultsSection.classList.remove('hidden');
    exportJsonBtn.disabled = false;

    if (report.error) {
        statStatus.textContent = 'ERR';
        statFindings.textContent = statCritical.textContent = statForms.textContent = '—';
        findingsList.innerHTML = `<div class="empty-state error-state">⚠ ${escHtml(report.error)}</div>`;
        formsList.innerHTML = '';
        return;
    }

    statStatus.textContent   = report.status_code || '—';
    statFindings.textContent = report.findings.length;
    statForms.textContent    = report.forms.length;
    vulnCount.textContent    = report.findings.length;

    const hc = report.findings.filter(f => { const s = getSeverity(f.type); return s==='critical'||s==='high'; }).length;
    statCritical.textContent = hc;

    findingsList.innerHTML = '';
    if (report.findings.length === 0) {
        findingsList.innerHTML = '<div class="success-state">✔ No vulnerabilities detected.</div>';
    } else {
        report.findings.forEach(f => findingsList.appendChild(buildFindingCard(f)));
    }

    formsList.innerHTML = '';
    if (report.forms.length === 0) {
        formsList.innerHTML = '<div class="empty-state">No forms detected.</div>';
    } else {
        report.forms.forEach(form => formsList.appendChild(buildFormCard(form)));
    }

    applyFilter(currentFilter);

    if (switchTab) {
        document.querySelector('[data-tab="scan"]').click();
    }
}

// ─── Finding Card ─────────────────────────────────────────────────────────────
function buildFindingCard(f) {
    const severity = getSeverity(f.type);
    const card = document.createElement('div');
    card.className = 'finding-card';
    card.dataset.severity = severity;

    let targetInfo = '';
    if (f.header)                  targetInfo = `Header: ${f.header}`;
    else if (f.cookie)             targetInfo = `Cookie: ${f.cookie}`;
    else if (f.action)             targetInfo = `Action: ${f.action}`;
    else if (f.details?.parameter) targetInfo = `Param: ${f.details.parameter}`;
    else if (f.details?.url)       targetInfo = `URL: ${f.details.url}`;
    else if (f.details?.path)      targetInfo = `Path: ${f.details.path}`;

    let detailRows = '';
    if (f.details && typeof f.details === 'object') {
        for (const [k,v] of Object.entries(f.details)) {
            if (v === null || v === undefined || v === '') continue;
            detailRows += `<div class="detail-block"><div class="detail-title">${k.toUpperCase().replace(/_/g,' ')}</div><div class="detail-value">${escHtml(String(v))}</div></div>`;
        }
    }

    const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(buildSearchQuery(f))}`;

    card.innerHTML = `
        <div class="finding-summary">
            <div class="finding-left">
                <div class="finding-type">${escHtml(f.type.replace(/_/g,' ').toUpperCase())}</div>
                <div class="finding-msg">${escHtml(f.msg || '')}</div>
                ${targetInfo ? `<div class="finding-target">${escHtml(targetInfo)}</div>` : ''}
            </div>
            <div class="finding-right">
                <span class="badge ${severity}">${severity.toUpperCase()}</span>
                <span class="expand-icon">▼</span>
            </div>
        </div>
        <div class="finding-details">
            ${detailRows || '<div class="detail-block"><div class="detail-value" style="color:var(--muted)">No additional details.</div></div>'}
            <a class="search-web-btn" href="${searchUrl}" target="_blank" rel="noopener noreferrer">
                <span>🔍</span> SEARCH ON WEB
            </a>
        </div>`;

    card.querySelector('.finding-summary').addEventListener('click', () => card.classList.toggle('expanded'));
    return card;
}

// ─── Form Card ────────────────────────────────────────────────────────────────
function buildFormCard(form) {
    const card = document.createElement('div');
    card.className = 'form-card';
    const tags = (form.inputs||[]).map(i => `<span class="form-input-tag">${escHtml(i.name||'?')} (${escHtml(i.type||'?')})</span>`).join('') || '<span class="form-input-tag">No inputs</span>';
    card.innerHTML = `<div class="form-method">${escHtml((form.method||'GET').toUpperCase())}</div><code class="form-action">${escHtml(form.action||'—')}</code><div class="form-inputs">${tags}</div>`;
    return card;
}

// ─── Filter ───────────────────────────────────────────────────────────────────
filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        filterBtns.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.dataset.filter;
        applyFilter(currentFilter);
    });
});

function applyFilter(filter) {
    document.querySelectorAll('.finding-card').forEach(card => {
        card.dataset.hidden = (filter !== 'all' && card.dataset.severity !== filter) ? 'true' : 'false';
    });
}

// ─── Export JSON ──────────────────────────────────────────────────────────────
exportJsonBtn.addEventListener('click', () => downloadJson(currentReport));

function downloadJson(report) {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], {type:'application/json'});
    triggerDownload(URL.createObjectURL(blob), 'scan_report.json');
}

function triggerDownload(url, filename) {
    const a = Object.assign(document.createElement('a'), {href: url, download: filename});
    document.body.appendChild(a); a.click(); a.remove();
}

// ─── History Tab ──────────────────────────────────────────────────────────────
function renderHistory() {
    const entries = loadHistory();
    const list    = document.getElementById('history-list');
    const empty   = document.getElementById('history-empty');
    const counter = document.getElementById('history-count');

    counter.textContent = entries.length ? entries.length : '';
    list.innerHTML = '';

    if (entries.length === 0) {
        empty.classList.remove('hidden');
        return;
    }
    empty.classList.add('hidden');

    entries.forEach(entry => {
        const el = document.createElement('div');
        el.className = 'history-entry';

        const date = new Date(entry.scanned_at).toLocaleString();
        const critHighLabel = entry.critical_high > 0
            ? `<span style="color:var(--red)">${entry.critical_high} CRITICAL/HIGH</span>`
            : `<span style="color:var(--green)">0 CRITICAL/HIGH</span>`;

        el.innerHTML = `
            <div class="he-left">
                <div class="he-url">${escHtml(entry.url)}</div>
                <div class="he-meta">
                    <span>🕐 ${escHtml(date)}</span>
                    <span>HTTP ${entry.status_code || 'N/A'}</span>
                    ${critHighLabel}
                </div>
            </div>
            <div class="he-right">
                <div class="he-vuln-badge">${entry.finding_count}</div>
                <button class="he-delete-btn" data-id="${entry.id}">✕</button>
            </div>`;

        // Click row → load that scan into the Scan tab
        el.addEventListener('click', e => {
            if (e.target.classList.contains('he-delete-btn')) return;
            renderReport(entry.report, true);
        });

        // Delete button
        el.querySelector('.he-delete-btn').addEventListener('click', e => {
            e.stopPropagation();
            deleteHistoryEntry(entry.id);
            renderHistory();
        });

        list.appendChild(el);
    });
}

// Clear all history
document.getElementById('clear-history-btn').addEventListener('click', () => {
    if (loadHistory().length === 0) return;
    if (confirm('Clear all scan history?')) {
        saveHistory([]);
        renderHistory();
    }
});

// ─── Reports Tab ──────────────────────────────────────────────────────────────
function renderReportTab() {
    const noScan  = document.getElementById('report-no-scan');
    const ready   = document.getElementById('report-ready');

    if (!currentReport || currentReport.error) {
        noScan.classList.remove('hidden');
        ready.classList.add('hidden');
        return;
    }

    noScan.classList.add('hidden');
    ready.classList.remove('hidden');

    document.getElementById('rpt-url').textContent    = currentReport.url;
    document.getElementById('rpt-time').textContent   = new Date(currentReport.scanned_at || Date.now()).toLocaleString();
    document.getElementById('rpt-count').textContent  = `${currentReport.findings.length} findings`;
    document.getElementById('rpt-status').textContent = currentReport.status_code || 'N/A';

    // Build and show the HTML preview in an iframe
    const html = buildHtmlReport(currentReport);
    const preview = document.getElementById('report-preview');
    preview.innerHTML = '';
    const iframe = document.createElement('iframe');
    iframe.sandbox = 'allow-same-origin';
    preview.appendChild(iframe);
    iframe.contentDocument.open();
    iframe.contentDocument.write(html);
    iframe.contentDocument.close();
}

// Download HTML
document.getElementById('dl-html-btn').addEventListener('click', () => {
    if (!currentReport) return;
    const html = buildHtmlReport(currentReport);
    const blob = new Blob([html], {type: 'text/html'});
    triggerDownload(URL.createObjectURL(blob), 'scan_report.html');
});

// Download JSON (second button in reports tab)
document.getElementById('dl-json-btn2').addEventListener('click', () => downloadJson(currentReport));

// ─── HTML Report Builder ──────────────────────────────────────────────────────
function buildHtmlReport(report) {
    const SEV_COLOR = { critical:'#ff4d6d', high:'#ff8c42', medium:'#ffd166', info:'#4cc9f0' };
    const date = new Date(report.scanned_at || Date.now()).toLocaleString();

    const critCount = report.findings.filter(f => getSeverity(f.type)==='critical').length;
    const highCount = report.findings.filter(f => getSeverity(f.type)==='high').length;
    const medCount  = report.findings.filter(f => getSeverity(f.type)==='medium').length;
    const infoCount = report.findings.filter(f => getSeverity(f.type)==='info').length;

    const findingRows = report.findings.map((f, i) => {
        const sev   = getSeverity(f.type);
        const color = SEV_COLOR[sev];
        const details = f.details ? Object.entries(f.details)
            .filter(([,v]) => v !== null && v !== undefined && v !== '')
            .map(([k,v]) => `<tr><td style="color:#888;font-size:11px;padding:3px 8px;white-space:nowrap">${k.toUpperCase()}</td><td style="font-size:12px;padding:3px 8px;word-break:break-all">${escHtml(String(v))}</td></tr>`)
            .join('') : '';
        const searchUrl = `https://www.google.com/search?q=${encodeURIComponent(buildSearchQuery(f))}`;
        return `
        <tr style="border-bottom:1px solid #222">
            <td style="padding:12px 10px;vertical-align:top;text-align:center">
                <span style="background:${color}22;color:${color};border:1px solid ${color}55;padding:2px 7px;border-radius:3px;font-size:10px;font-weight:700">${sev.toUpperCase()}</span>
            </td>
            <td style="padding:12px 10px;vertical-align:top">
                <div style="font-size:11px;color:#00ff88;font-weight:700;margin-bottom:4px">${escHtml(f.type.replace(/_/g,' ').toUpperCase())}</div>
                <div style="font-size:12px;color:#c8d6e5;margin-bottom:6px">${escHtml(f.msg||'')}</div>
                ${details ? `<table style="width:100%;background:#0a0a0a;border-radius:4px;margin-bottom:8px">${details}</table>` : ''}
                <a href="${searchUrl}" target="_blank" style="color:#4cc9f0;font-size:11px;text-decoration:none;border:1px solid #4cc9f055;padding:2px 8px;border-radius:3px">🔍 Search on Web</a>
            </td>
        </tr>`;
    }).join('');

    const formRows = report.forms.map(form => {
        const inputs = (form.inputs||[]).map(i => `<span style="background:#1a1a1a;border:1px solid #333;padding:1px 6px;border-radius:3px;font-size:10px;margin:2px;display:inline-block">${escHtml(i.name||'?')} (${escHtml(i.type||'?')})</span>`).join('');
        return `<tr style="border-bottom:1px solid #1a1a1a"><td style="padding:10px;vertical-align:top"><span style="color:#ff8c42;font-weight:700;font-size:11px">${escHtml((form.method||'GET').toUpperCase())}</span><br><span style="color:#6b7a8d;font-size:11px">${escHtml(form.action||'—')}</span></td><td style="padding:10px">${inputs}</td></tr>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>OWASP Scan Report — ${escHtml(report.url)}</title>
<style>
  body{margin:0;background:#0a0c0e;color:#c8d6e5;font-family:'Courier New',monospace;font-size:13px}
  h1{font-family:sans-serif;font-size:22px;font-weight:900;color:#00ff88;letter-spacing:0.05em}
  h2{font-size:13px;letter-spacing:0.1em;color:#6b7a8d;margin:24px 0 10px;border-bottom:1px solid #1a2a1a;padding-bottom:6px}
  table{width:100%;border-collapse:collapse}
  .stat{display:inline-block;background:#141820;border:1px solid #1a2a1a;border-radius:6px;padding:12px 20px;margin:6px;min-width:100px;text-align:center}
  .stat-n{font-family:sans-serif;font-size:28px;font-weight:900}
  .stat-l{font-size:10px;color:#4a5568;letter-spacing:0.1em;margin-top:2px}
</style>
</head>
<body>
<div style="max-width:900px;margin:0 auto;padding:32px 24px">

  <div style="border-bottom:1px solid #1a2a1a;padding-bottom:20px;margin-bottom:24px">
    <h1>🛡 OWASP MINI-SCANNER REPORT</h1>
    <div style="color:#4a5568;font-size:11px;margin-top:6px">Generated: ${escHtml(date)}</div>
  </div>

  <h2>// TARGET</h2>
  <table style="background:#0f1214;border:1px solid #1a2a1a;border-radius:6px">
    <tr><td style="padding:8px 14px;color:#4a5568;font-size:11px;width:120px">URL</td><td style="padding:8px 14px;color:#00ff88">${escHtml(report.url)}</td></tr>
    <tr><td style="padding:8px 14px;color:#4a5568;font-size:11px">HTTP STATUS</td><td style="padding:8px 14px">${report.status_code || 'N/A'}</td></tr>
    <tr><td style="padding:8px 14px;color:#4a5568;font-size:11px">SCANNED AT</td><td style="padding:8px 14px">${escHtml(date)}</td></tr>
  </table>

  <h2>// SUMMARY</h2>
  <div>
    <div class="stat"><div class="stat-n" style="color:#ff4d6d">${critCount}</div><div class="stat-l">CRITICAL</div></div>
    <div class="stat"><div class="stat-n" style="color:#ff8c42">${highCount}</div><div class="stat-l">HIGH</div></div>
    <div class="stat"><div class="stat-n" style="color:#ffd166">${medCount}</div><div class="stat-l">MEDIUM</div></div>
    <div class="stat"><div class="stat-n" style="color:#4cc9f0">${infoCount}</div><div class="stat-l">INFO</div></div>
    <div class="stat"><div class="stat-n">${report.findings.length}</div><div class="stat-l">TOTAL</div></div>
    <div class="stat"><div class="stat-n" style="color:#4cc9f0">${report.forms.length}</div><div class="stat-l">FORMS</div></div>
  </div>

  <h2>// VULNERABILITIES</h2>
  ${report.findings.length === 0
    ? '<div style="color:#00ff88;padding:16px">✔ No vulnerabilities found.</div>'
    : `<table style="background:#0f1214;border:1px solid #1a2a1a;border-radius:6px">${findingRows}</table>`}

  <h2>// EXTRACTED FORMS</h2>
  ${report.forms.length === 0
    ? '<div style="color:#4a5568;padding:16px">No forms detected.</div>'
    : `<table style="background:#0f1214;border:1px solid #1a2a1a;border-radius:6px">${formRows}</table>`}

  <div style="margin-top:32px;padding-top:16px;border-top:1px solid #1a2a1a;font-size:10px;color:#2a3a2a;text-align:center">
    OWASP Mini-Scanner v0.3 — For authorized testing only
  </div>
</div>
</body>
</html>`;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function showError(msg) {
    resultsSection.classList.remove('hidden');
    findingsList.innerHTML = `<div class="empty-state error-state">⚠ ${escHtml(msg)}</div>`;
}

function escHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
