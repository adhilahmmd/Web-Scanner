/**
 * WebSecuity – Main Application Logic
 * SPA navigation, scan wizard flow, results rendering, modal, toast, filters.
 */

/* ══════════════════════════════════════════════
   Constants
   ══════════════════════════════════════════════ */
const MODULE_NAMES = {
  crawler: 'Web Crawler',
  sqli:    'SQL Injection',
  xss:     'XSS Scanner',
  bac:     'Access Control',
  auth:    'Auth & Session',
  ssl:     'SSL/TLS',
  headers: 'HTTP Headers',
};

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_COLORS = {
  critical: '#ff2d55',
  high:     '#ff6b35',
  medium:   '#ffd60a',
  low:      '#34c759',
  info:     '#636e7b',
};

const CONF_COLORS = {
  high:   '#34c759',
  medium: '#ffd60a',
  low:    '#636e7b',
};

/* ══════════════════════════════════════════════
   App State
   ══════════════════════════════════════════════ */
const state = {
  currentPage: 'dashboard',
  scanResults: null,
  allFindings: [],
  scanning: false,
  wizardStep: 1,  // 1 = Target+Crawler, 2 = Modules+Scope, 3 = Active Scan
  currentJobId: null,
};

/* ══════════════════════════════════════════════
   DOM helpers
   ══════════════════════════════════════════════ */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];

/* ══════════════════════════════════════════════
   Navigation
   ══════════════════════════════════════════════ */
function navigate(page) {
  if (state.scanning && page !== 'scanner') {
    toast('Scan in progress — please wait.', 'info');
    return;
  }
  state.currentPage = page;

  $$('.page').forEach(p => p.classList.remove('active'));
  $$('.nav-item').forEach(n => n.classList.remove('active'));

  $(`#page-${page}`).classList.add('active');
  $(`#nav-${page}`)?.classList.add('active');

  // Reset wizard to step 1 when navigating to scanner
  if (page === 'scanner' && !state.scanning) {
    goToStep(1);
  }

  // Close mobile sidebar
  $('#sidebar').classList.remove('open');
}

/* ══════════════════════════════════════════════
   Toast notifications
   ══════════════════════════════════════════════ */
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = msg;
  $('#toast-container').appendChild(el);
  setTimeout(() => el.remove(), 4000);
}
window.showToast = toast;

/* ══════════════════════════════════════════════
   Server Status Check
   ══════════════════════════════════════════════ */
async function checkServerStatus() {
  const dot = document.querySelector('.status-dot');
  const label = document.querySelector('.server-status span');
  try {
    await window.api.health();
    dot.className = 'status-dot online';
    label.textContent = 'API Online';
  } catch {
    dot.className = 'status-dot offline';
    label.textContent = 'API Offline';
  }
}

/* ══════════════════════════════════════════════
   Scan Log
   ══════════════════════════════════════════════ */
function addLog(msg, type = 'info') {
  const log = $('#scan-log');
  if (!log) return;
  const line = document.createElement('div');
  line.className = `log-line log-${type}`;
  line.textContent = msg;
  log.appendChild(line);
  log.scrollTop = log.scrollHeight;
}

function setProgress(pct) {
  const bar = $('#progress-bar');
  const label = $('#progress-percent');
  if (bar) bar.style.width = `${pct}%`;
  if (label) label.textContent = `${pct}%`;
}

/* ══════════════════════════════════════════════
   Wizard Step Management
   ══════════════════════════════════════════════ */
function goToStep(n) {
  state.wizardStep = n;

  // Show/hide step panels
  $$('.wizard-step-panel').forEach(panel => panel.classList.remove('active'));
  const panel = $(`#wizard-step-${n}`);
  if (panel) panel.classList.add('active');

  // Update stepper indicator
  $$('.step-indicator').forEach((el, i) => {
    el.classList.remove('active', 'done');
    if (i + 1 < n) el.classList.add('done');
    else if (i + 1 === n) el.classList.add('active');
  });
}

/* ══════════════════════════════════════════════
   Crawler Toggle
   ══════════════════════════════════════════════ */
function isCrawlerEnabled() {
  const toggle = $('#crawler-toggle-on');
  return toggle ? toggle.checked : true;
}

function updateCrawlerControls() {
  const enabled = isCrawlerEnabled();
  const controls = $('#crawler-controls');
  if (controls) {
    controls.style.opacity = enabled ? '1' : '0.35';
    controls.style.pointerEvents = enabled ? 'auto' : 'none';
  }
}

/* ══════════════════════════════════════════════
   Scan Flow
   ══════════════════════════════════════════════ */
async function launchScan() {
  // ── Collect Step 1 ──
  const urlInput = $('#target-url');
  const url = urlInput.value.trim();

  if (!url) { toast('Please enter a target URL.', 'error'); urlInput.focus(); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    toast('URL must start with http:// or https://', 'error');
    return;
  }

  const useCrawler = isCrawlerEnabled();
  const maxDepth   = parseInt($('#crawl-depth')?.value) || 2;
  const maxPages   = parseInt($('#crawl-max-links')?.value) || 20;
  const timeout    = parseInt($('#scan-timeout')?.value) || 15;

  // ── Collect Step 2 ──
  const modules = $$('input[name="module"]:checked').map(cb => cb.value);
  if (modules.length === 0) {
    toast('Select at least one scanner module.', 'error');
    goToStep(2);
    return;
  }
  
  if (useCrawler && !modules.includes('crawler')) {
    modules.push('crawler');
  }
  const scanAllLinks = $('input[name="scan-scope"][value="all"]')?.checked ?? true;

  const crawlerConfig = { use_crawler: useCrawler, max_depth: maxDepth, max_pages: maxPages, scan_all_links: scanAllLinks };

  // ── Switch to Step 3 (active scan) ──
  goToStep(3);
  state.scanning = true;
  updateScanButton(true);
  showScanActive(url);

  // Reset log
  $('#scan-log').innerHTML = '';
  addLog(`[ * ] Starting scan on: ${url}`, 'info');
  addLog(`[ * ] Modules: ${modules.join(', ')}`, 'info');
  addLog(`[ * ] Crawler: ${useCrawler ? `ON (depth=${maxDepth}, max=${maxPages} links, scope=${scanAllLinks ? 'all' : 'seed only'})` : 'OFF'}`, 'info');
  addLog(`[ * ] Timeout: ${timeout}s per module`, 'muted');
  addLog('', 'muted');

  setProgress(5);

  try {
    const pollResult = await window.api.runModules(
      url, modules, timeout, crawlerConfig,
      (pct) => setProgress(pct),
      (jobId) => { state.currentJobId = jobId; }
    );

    setProgress(100);
    addLog('', 'muted');
    addLog('[ ✓ ] Scan complete! Processing results...', 'success');

    // pollResult IS the full unified result object from the backend
    const moduleResults = pollResult.results || {};
    const modulesCompleted = pollResult.modules_completed || modules;
    const modulesFailed    = pollResult.modules_failed || [];

    // Log per-module status
    for (const mod of modules) {
      const data = moduleResults[mod];
      if (modulesFailed.includes(mod)) {
        const errMsg = (data && data.error) ? data.error : 'Unknown error';
        addLog(`[ ✗ ] ${MODULE_NAMES[mod] || mod}: FAILED — ${errMsg}`, 'error');
      } else if (data) {
        const count = (data.findings || []).length;
        const severity = data.summary?.risk_level || data.summary?.grade || '—';
        addLog(`[ ✓ ] ${MODULE_NAMES[mod] || mod}: ${count} finding(s) | Risk: ${severity}`, 'success');
      }
    }

    // Build findings from the returned results
    const allFindings = buildFindingsList(moduleResults, modules);
    const counts      = countSeverities(allFindings);
    const risk        = pollResult.overall_risk || topRisk(counts);

    const result = {
      url,
      modules_requested: modules,
      modules_completed: modulesCompleted,
      modules_failed:    modulesFailed,
      results:           moduleResults,
      total_vulnerabilities: pollResult.total_vulnerabilities ?? allFindings.length,
      critical_count: pollResult.critical_count ?? counts.critical,
      high_count:     pollResult.high_count ?? counts.high,
      medium_count:   pollResult.medium_count ?? counts.medium,
      low_count:      pollResult.low_count ?? counts.low,
      overall_risk:   risk,
    };

    state.scanResults = result;
    state.allFindings = allFindings;

    updateDashboardStats(result);

    setTimeout(() => {
      state.scanning = false;
      state.currentJobId = null;
      updateScanButton(false);
      
      const stopBtn = $('#stop-scan-btn');
      if (stopBtn) {
        stopBtn.disabled = false;
        stopBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12" rx="2"/></svg> Stop Scan`;
      }

      renderResults(result);
      navigate('results');
      if (window.auth?.isLoggedIn()) {
        window.api.saveScanHistory(result)
          .then(() => toast('Scan complete! Results saved to your history.', 'success'))
          .catch(err => toast('Scan complete, but saving to history failed: ' + err.message, 'error'));
      } else {
        toast('Scan complete!', 'success');
      }
    }, 800);

  } catch (err) {
    state.scanning = false;
    state.currentJobId = null;
    updateScanButton(false);
    
    const stopBtn = $('#stop-scan-btn');
    if (stopBtn) {
      stopBtn.disabled = false;
      stopBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12" rx="2"/></svg> Stop Scan`;
    }

    addLog(`[ ✗ ] Error: ${err.message}`, 'error');
    toast(`Scan stopped: ${err.message}`, 'error');
    // Allow going back to config
    setTimeout(() => goToStep(2), 1500);
  }
}

/* ══════════════════════════════════════════════
   Finding Helpers
   ══════════════════════════════════════════════ */
function buildFindingsList(moduleResults, modules) {
  const all = [];
  for (const mod of modules) {
    const data = moduleResults[mod];
    if (!data || data.error) continue;

    const findings = Array.isArray(data.findings) ? data.findings : [];
    for (const f of findings) {
      all.push({ ...f, _module: mod });
    }
  }
  return all;
}

function countSeverities(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const s = (f.severity || 'info').toLowerCase();
    if (s in counts) counts[s]++;
    else counts.info++;
  }
  return counts;
}

function topRisk(counts) {
  for (const s of SEV_ORDER) {
    if (counts[s] > 0) return s;
  }
  return 'info';
}

/* ══════════════════════════════════════════════
   Scan UI Helpers
   ══════════════════════════════════════════════ */
function updateScanButton(scanning) {
  const btn = $('#launch-scan-btn');
  if (!btn) return;
  btn.disabled = scanning;
  btn.querySelector('.btn-text').classList.toggle('hidden', scanning);
  btn.querySelector('.btn-loading').classList.toggle('hidden', !scanning);
}

function showScanActive(url) {
  $('#scan-idle').classList.add('hidden');
  $('#scan-active').classList.remove('hidden');
  $('#scan-target-url').textContent = url;
  setProgress(0);
}

function updateDashboardStats(result) {
  const el = (id) => document.getElementById(id);
  if (el('stat-last-critical')) el('stat-last-critical').textContent = result.critical_count;
  if (el('stat-last-high'))     el('stat-last-high').textContent     = result.high_count;
  if (el('stat-last-total'))    el('stat-last-total').textContent    = result.total_vulnerabilities;
}

/* ══════════════════════════════════════════════
   Results Rendering
   ══════════════════════════════════════════════ */
function renderResults(result) {
  $('#results-empty').classList.add('hidden');
  $('#results-content').classList.remove('hidden');
  $('#copy-json-btn').disabled = false;
  $('#download-report-btn').disabled = false;
  $('#results-subtitle').textContent = `Scanned: ${result.url} — ${result.total_vulnerabilities} findings`;

  const risk = result.overall_risk || 'info';
  const riskBadge = $('#risk-badge');
  riskBadge.textContent = risk.toUpperCase();
  riskBadge.className = `risk-badge risk-${risk}`;
  $('#risk-url').textContent = result.url;

  $('#count-critical').textContent = result.critical_count || 0;
  $('#count-high').textContent     = result.high_count || 0;
  $('#count-medium').textContent   = result.medium_count || 0;
  $('#count-low').textContent      = result.low_count || 0;
  $('#count-total').textContent    = result.total_vulnerabilities || 0;

  const chart = new DonutChart('severity-chart', 'chart-legend');
  const counts = countSeverities(state.allFindings);
  chart.draw([
    { label: 'Critical', value: counts.critical, color: SEV_COLORS.critical },
    { label: 'High',     value: counts.high,     color: SEV_COLORS.high },
    { label: 'Medium',   value: counts.medium,   color: SEV_COLORS.medium },
    { label: 'Low',      value: counts.low,      color: SEV_COLORS.low },
    { label: 'Info',     value: counts.info,     color: SEV_COLORS.info },
  ]);

  renderModuleStatus(result);
  renderFindingsTable(state.allFindings);
}

function renderModuleStatus(result) {
  const container = $('#modules-status-list');
  if (!container) return;

  const mods = result.modules_requested || [];
  container.innerHTML = mods.map(mod => {
    const data = result.results?.[mod];
    const failed = result.modules_failed?.includes(mod);
    const findings = Array.isArray(data?.findings) ? data.findings : [];
    
    if (mod === 'crawler') {
      const pagesCount = Array.isArray(data?.pages_crawled) ? data.pages_crawled.length : 0;
      const linksCount = Array.isArray(data?.all_links) ? data.all_links.length : 0;
      
      let rowStyle = 'display: flex; align-items: center; gap: 8px;';
      let rowAction = '';
      
      if (!failed && (linksCount > 0 || data?.api_endpoints?.length > 0 || data?.forms?.length > 0)) {
        rowStyle += ' cursor: pointer;';
        rowAction = `onclick="window.app.openCrawlerModal()" title="Click to view crawler data"`;
      }

      let badgeClass = failed ? 'badge-error' : 'badge-info';
      let badgeText = failed ? 'Error' : 'Data Ready';

      return `
        <div class="module-status-item crawler-status-item" style="${rowStyle}" ${rowAction}>
          <span class="module-status-name">${MODULE_NAMES[mod] || mod}</span>
          <span class="module-status-badge ${badgeClass}">${badgeText}</span>
          <span class="module-status-count" style="flex: 1;">${linksCount} links · ${pagesCount} pages</span>
        </div>
      `;
    }

    // Default module logic
    const criticalCount = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const hasFindings = findings.length > 0;

    let badgeClass = 'badge-info';
    let badgeText = 'No findings';
    if (failed) { badgeClass = 'badge-error'; badgeText = 'Error'; }
    else if (criticalCount > 0) { badgeClass = 'badge-error'; badgeText = 'Critical'; }
    else if (hasFindings) { badgeClass = 'badge-warn'; badgeText = 'Findings'; }
    else if (data && !failed) { badgeClass = 'badge-ok'; badgeText = 'Clean'; }

    let extra = '';
    if (mod === 'headers' && data?.summary?.grade) extra = ` · Grade ${data.summary.grade}`;
    if (mod === 'ssl' && data?.summary?.grade) extra = ` · Grade ${data.summary.grade}`;

    return `
      <div class="module-status-item" style="display: flex; align-items: center; gap: 8px;">
        <span class="module-status-name">${MODULE_NAMES[mod] || mod}</span>
        <span class="module-status-badge ${badgeClass}">${badgeText}</span>
        <span class="module-status-count" style="flex: 1;">${findings.length} findings${extra}</span>
      </div>
    `;
  }).join('');
}

function renderFindingsTable(findings, severityFilter = '', moduleFilter = '') {
  const tbody = $('#findings-tbody');
  if (!tbody) return;

  let filtered = findings;
  if (severityFilter) filtered = filtered.filter(f => (f.severity || '').toLowerCase() === severityFilter);
  if (moduleFilter) filtered = filtered.filter(f => f._module === moduleFilter);

  const empty = $('#findings-empty-table');

  if (filtered.length === 0) {
    tbody.innerHTML = '';
    empty.classList.remove('hidden');
    return;
  }

  empty.classList.add('hidden');

  const sevIdx = (s) => SEV_ORDER.indexOf((s || '').toLowerCase());
  filtered.sort((a, b) => sevIdx(a.severity) - sevIdx(b.severity));

  tbody.innerHTML = filtered.map((f, i) => {
    const sev = (f.severity || 'info').toLowerCase();
    const conf = (f.confidence || '').toLowerCase();
    const mod = f._module || '';
    const desc = f.description || f.evidence || '—';
    const param = f.parameter || f.header_name || f.check_type || '—';

    const confBadge = conf
      ? `<span class="conf-badge" style="background:${CONF_COLORS[conf] || '#636e7b'}22;color:${CONF_COLORS[conf] || '#636e7b'};border:1px solid ${CONF_COLORS[conf] || '#636e7b'}44;border-radius:4px;font-size:0.65rem;padding:1px 5px;margin-left:4px;vertical-align:middle">${conf.toUpperCase()}</span>`
      : '';

    return `
      <tr data-idx="${i}">
        <td><span class="sev-badge sev-badge-${sev}">${sev.toUpperCase()}</span>${confBadge}</td>
        <td><span class="module-badge">${MODULE_NAMES[mod] || mod}</span></td>
        <td class="cell-desc">${escapeHtml(desc.substring(0, 120))}${desc.length > 120 ? '...' : ''}</td>
        <td class="cell-param" title="${escapeHtml(param)}">${escapeHtml(param)}</td>
        <td><button class="details-btn" data-idx="${i}">View</button></td>
      </tr>
    `;
  }).join('');

  tbody.querySelectorAll('.details-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openFindingModal(filtered[parseInt(btn.dataset.idx)]);
    });
  });
  tbody.querySelectorAll('tr[data-idx]').forEach(row => {
    row.addEventListener('click', () => {
      openFindingModal(filtered[parseInt(row.dataset.idx)]);
    });
  });
}

/* ══════════════════════════════════════════════
   Finding Detail Modal
   ══════════════════════════════════════════════ */
function openFindingModal(finding) {
  const modal = $('#modal-overlay');
  const title = $('#modal-title');
  const body  = $('#modal-body');
  if (!modal || !finding) return;

  const sev = (finding.severity || 'info').toLowerCase();
  const conf = (finding.confidence || '').toLowerCase();
  title.textContent = finding.description || finding.check_type || 'Finding Detail';

  const confColor = CONF_COLORS[conf] || '#636e7b';
  const confBadgeHtml = conf
    ? `<span style="background:${confColor}22;color:${confColor};border:1px solid ${confColor}44;border-radius:4px;padding:2px 8px;font-size:0.75rem;font-weight:600">${conf.toUpperCase()} CONFIDENCE</span>`
    : '';

  const rows = [
    { label: 'Severity', value: `<span class="sev-badge sev-badge-${sev}">${sev.toUpperCase()}</span>` },
    conf ? { label: 'Confidence', value: confBadgeHtml, raw: true } : null,
    { label: 'Module', value: `<span class="module-badge">${MODULE_NAMES[finding._module] || finding._module || '—'}</span>` },
    finding.parameter ? { label: 'Parameter / Field', value: `<div class="detail-value monospace">${escapeHtml(finding.parameter)}</div>`, raw: true } : null,
    finding.header_name ? { label: 'Header', value: `<div class="detail-value monospace">${escapeHtml(finding.header_name)}</div>`, raw: true } : null,
    finding.check_type ? { label: 'Check Type', value: finding.check_type } : null,
    finding.xss_type ? { label: 'XSS Type', value: finding.xss_type } : null,
    finding.injection_point ? { label: 'Injection Point', value: finding.injection_point } : null,
    (finding.payloads_tested && finding.payloads_tested.length > 0)
      ? { label: `Payloads Tested (${finding.payloads_tested.length})`, value: `<div class="detail-value monospace">${escapeHtml(finding.payloads_tested.join(', '))}</div>`, raw: true }
      : finding.payload ? { label: 'Payload Used', value: `<div class="detail-value monospace">${escapeHtml(finding.payload)}</div>`, raw: true } : null,
    finding.evidence ? { label: 'Evidence', value: `<div class="detail-value monospace">${escapeHtml(finding.evidence.substring(0, 500))}</div>`, raw: true } : null,
    finding.description ? { label: 'Description', value: finding.description } : null,
    finding.remediation ? { label: 'Remediation', value: `<div class="detail-value remediation">${escapeHtml(finding.remediation)}</div>`, raw: true } : null,
  ].filter(Boolean);

  body.innerHTML = rows.map(r => `
    <div class="detail-row">
      <span class="detail-label">${r.label}</span>
      ${r.raw ? r.value : `<div class="detail-value">${escapeHtml(String(r.value))}</div>`}
    </div>
  `).join('');

  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function openCrawlerModal() {
  const modal = $('#modal-overlay');
  const title = $('#modal-title');
  const body  = $('#modal-body');
  if (!modal || !state.scanResults || !state.scanResults.results.crawler) return;

  const data = state.scanResults.results.crawler;
  title.textContent = 'Web Crawler Data';

  const rows = [];

  if (data.pages_crawled && data.pages_crawled.length > 0) {
    rows.push({ label: `Crawled Pages (${data.pages_crawled.length})`, value: `<div class="detail-value monospace" style="max-height:150px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(data.pages_crawled.join('\\n'))}</div>`, raw: true });
  }
  if (data.all_links && data.all_links.length > 0) {
    rows.push({ label: `Discovered Links (${data.all_links.length})`, value: `<div class="detail-value monospace" style="max-height:150px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(data.all_links.join('\\n'))}</div>`, raw: true });
  }
  if (data.api_endpoints && data.api_endpoints.length > 0) {
    const eps = data.api_endpoints.map(e => typeof e === 'string' ? e : e.endpoint || JSON.stringify(e));
    rows.push({ label: `API Endpoints (${eps.length})`, value: `<div class="detail-value monospace" style="max-height:150px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(eps.join('\\n'))}</div>`, raw: true });
  }
  if (data.forms && data.forms.length > 0) {
    const formsStr = data.forms.map(f => {
       let str = `Action: ${f.action} | Method: ${f.method}`;
       if (f.inputs && f.inputs.length > 0) {
         const inputsStr = f.inputs.map(i => `${i.name || 'unnamed'}(${i.input_type || 'text'})`).join(', ');
         str += ` | Inputs: [ ${inputsStr} ]`;
       }
       return str;
    }).join('\\n\\n');
    rows.push({ label: `Discovered Forms (${data.forms.length})`, value: `<div class="detail-value monospace" style="max-height:150px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(formsStr)}</div>`, raw: true });
  }
  if (data.hidden_paths && data.hidden_paths.length > 0) {
    rows.push({ label: `Hidden Paths (${data.hidden_paths.length})`, value: `<div class="detail-value monospace" style="max-height:150px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(data.hidden_paths.join('\\n'))}</div>`, raw: true });
  }
  if (data.js_files && data.js_files.length > 0) {
    rows.push({ label: `JS Files (${data.js_files.length})`, value: `<div class="detail-value monospace" style="max-height:150px; overflow-y:auto; white-space:pre-wrap;">${escapeHtml(data.js_files.join('\\n'))}</div>`, raw: true });
  }

  if (rows.length === 0) {
    body.innerHTML = '<p style="padding:16px;">No crawler data found.</p>';
  } else {
    body.innerHTML = rows.map(r => `
      <div class="detail-row">
        <span class="detail-label">${r.label}</span>
        ${r.raw ? r.value : `<div class="detail-value">${escapeHtml(String(r.value))}</div>`}
      </div>
    `).join('');
  }

  modal.classList.remove('hidden');
  document.body.style.overflow = 'hidden';
}

function closeFindingModal() {
  $('#modal-overlay')?.classList.add('hidden');
  document.body.style.overflow = '';
}

/* ══════════════════════════════════════════════
   Export Helpers
   ══════════════════════════════════════════════ */
function showDownloadModal() {
  if (!state.scanResults) return;
  const overlay = $('#download-modal-overlay');
  if (overlay) {
    overlay.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }
}

function closeDownloadModal() {
  const overlay = $('#download-modal-overlay');
  if (overlay) overlay.classList.add('hidden');
  document.body.style.overflow = '';
}

function exportJSON() {
  if (!state.scanResults) return;
  closeDownloadModal();
  const json = JSON.stringify(state.scanResults, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = `websecuity-scan-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('JSON report downloaded!', 'success');
}

function exportPDF() {
  if (!state.scanResults) return;
  closeDownloadModal();

  const r = state.scanResults;
  const findings = state.allFindings;
  const ts = new Date().toLocaleString();
  const SEV_COLORS_PDF = {
    critical: '#ff2d55', high: '#ff6b35', medium: '#ffd60a', low: '#34c759', info: '#636e7b'
  };

  const findingRows = findings.map(f => {
    const sev = (f.severity || 'info').toLowerCase();
    const col = SEV_COLORS_PDF[sev] || '#636e7b';
    const mod = MODULE_NAMES[f._module] || f._module || '—';
    const desc = escapeHtml((f.description || f.evidence || '—').substring(0, 180));
    const param = escapeHtml(f.parameter || f.header_name || f.check_type || '—');
    return `
      <tr>
        <td><span style="background:${col}22;color:${col};border:1px solid ${col}44;border-radius:4px;padding:2px 7px;font-size:11px;font-weight:700">${sev.toUpperCase()}</span></td>
        <td style="color:#7b2fff;font-weight:600">${mod}</td>
        <td>${desc}</td>
        <td style="font-family:monospace;font-size:11px">${param}</td>
      </tr>`;
  }).join('');

  const riskColor = SEV_COLORS_PDF[r.overall_risk] || '#636e7b';

  const html = `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>WebSecuity Scan Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; color: #1a1a2e; background: #fff; font-size: 13px; line-height: 1.6; }
  .cover { background: linear-gradient(135deg, #07091a 0%, #111630 100%); color: #fff; padding: 48px 56px 40px; page-break-after: always; }
  .cover-logo { font-size: 28px; font-weight: 900; letter-spacing: -0.5px; margin-bottom: 8px; }
  .cover-logo span { background: linear-gradient(90deg, #00d4ff, #7b2fff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .cover-sub { font-size: 13px; color: rgba(255,255,255,0.5); margin-bottom: 48px; }
  .cover-url { font-size: 18px; font-weight: 700; color: #00d4ff; margin-bottom: 8px; word-break: break-all; }
  .cover-ts { font-size: 12px; color: rgba(255,255,255,0.4); margin-bottom: 40px; }
  .cover-risk { display: inline-block; font-size: 22px; font-weight: 900; padding: 10px 24px; border-radius: 8px; background: ${riskColor}22; color: ${riskColor}; border: 2px solid ${riskColor}66; }
  .stats { display: flex; gap: 20px; margin-top: 36px; }
  .stat-box { background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); border-radius: 10px; padding: 16px 22px; flex: 1; text-align: center; }
  .stat-num { font-size: 32px; font-weight: 900; }
  .stat-lbl { font-size: 10px; color: rgba(255,255,255,0.4); text-transform: uppercase; letter-spacing: 0.8px; margin-top: 2px; }
  .section { padding: 36px 56px; }
  .section-title { font-size: 16px; font-weight: 800; color: #07091a; margin-bottom: 20px; padding-bottom: 8px; border-bottom: 2px solid #00d4ff; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: #f0f4f8; color: #4a5568; font-weight: 700; text-transform: uppercase; font-size: 10px; letter-spacing: 0.6px; padding: 8px 12px; text-align: left; }
  td { padding: 9px 12px; border-bottom: 1px solid #e8edf2; vertical-align: top; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #f8fafc; }
  .footer { text-align: center; padding: 20px; font-size: 11px; color: #9ba8b8; border-top: 1px solid #e8edf2; }
  @media print { body { -webkit-print-color-adjust: exact; print-color-adjust: exact; } }
</style>
</head>
<body>
  <div class="cover">
    <div class="cover-logo"><span>WebSecuity</span></div>
    <div class="cover-sub">Vulnerability Scan Report</div>
    <div class="cover-url">${escapeHtml(r.url)}</div>
    <div class="cover-ts">Generated: ${ts}</div>
    <div class="cover-risk">RISK: ${(r.overall_risk || 'INFO').toUpperCase()}</div>
    <div class="stats">
      <div class="stat-box"><div class="stat-num" style="color:#ff2d55">${r.critical_count || 0}</div><div class="stat-lbl">Critical</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#ff6b35">${r.high_count || 0}</div><div class="stat-lbl">High</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#ffd60a">${r.medium_count || 0}</div><div class="stat-lbl">Medium</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#34c759">${r.low_count || 0}</div><div class="stat-lbl">Low</div></div>
      <div class="stat-box"><div class="stat-num" style="color:#00d4ff">${r.total_vulnerabilities || 0}</div><div class="stat-lbl">Total</div></div>
    </div>
  </div>
  <div class="section">
    <div class="section-title">Vulnerability Findings</div>
    ${findings.length === 0 ? '<p style="color:#636e7b;padding:16px 0">No findings were reported in this scan.</p>' : `
    <table>
      <thead><tr><th>Severity</th><th>Module</th><th>Description</th><th>Parameter / Header</th></tr></thead>
      <tbody>${findingRows}</tbody>
    </table>`}
  </div>
  <div class="footer">WebSecuity &mdash; Automated Web Vulnerability Scanner &mdash; ${ts}</div>
</body>
</html>`;

  const win = window.open('', '_blank');
  if (!win) { toast('Pop-up blocked — please allow pop-ups for this site.', 'error'); return; }
  win.document.write(html);
  win.document.close();
  win.focus();
  setTimeout(() => {
    win.print();
    toast('PDF ready — use your browser\'s print dialog to save as PDF.', 'success');
  }, 500);
}

function copyJSON() {
  if (!state.scanResults) return;
  navigator.clipboard.writeText(JSON.stringify(state.scanResults, null, 2))
    .then(() => toast('JSON copied to clipboard!', 'success'))
    .catch(() => toast('Copy failed — use Download instead.', 'error'));
}

/* ══════════════════════════════════════════════
   Utilities
   ══════════════════════════════════════════════ */
function escapeHtml(str) {
  if (typeof str !== 'string') str = String(str);
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatDate(isoStr) {
  try {
    const d = new Date(isoStr);
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' }) +
      ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  } catch { return isoStr; }
}

/* ══════════════════════════════════════════════
   History Page
   ══════════════════════════════════════════════ */
const SHORT_MODULE_NAMES = {
  crawler: 'Crawler', sqli: 'SQLi', xss: 'XSS', bac: 'BAC',
  auth: 'Auth', ssl: 'SSL', headers: 'Headers',
};

async function loadHistory() {
  const loading = $('#history-loading');
  const empty   = $('#history-empty');
  const list    = $('#history-list');
  if (!loading || !list) return;

  loading.classList.remove('hidden');
  empty.classList.add('hidden');
  list.innerHTML = '';

  try {
    const scans = await window.auth.fetchHistory();
    loading.classList.add('hidden');

    if (!scans || scans.length === 0) {
      empty.classList.remove('hidden');
      return;
    }

    $('#history-subtitle').textContent = `${scans.length} saved scan${scans.length !== 1 ? 's' : ''}`;
    list.innerHTML = scans.map(scan => renderHistoryCard(scan)).join('');

    list.querySelectorAll('.history-card').forEach(card => {
      card.addEventListener('click', (e) => {
        if (e.target.closest('.history-delete-btn')) return;
        loadHistoryScanResults(parseInt(card.dataset.id));
      });
    });
    list.querySelectorAll('.history-delete-btn').forEach(btn => {
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const id = parseInt(btn.dataset.id);
        try {
          await window.auth.deleteScan(id);
          toast('Scan deleted from history.', 'info');
          loadHistory();
        } catch (err) {
          toast('Could not delete scan: ' + err.message, 'error');
        }
      });
    });
  } catch (err) {
    loading.classList.add('hidden');
    toast('Failed to load history: ' + err.message, 'error');
  }
}

function renderHistoryCard(scan) {
  const risk = scan.risk_level || 'info';
  const modules = (scan.modules_run || []).map(m =>
    `<span class="history-module-tag">${SHORT_MODULE_NAMES[m] || m}</span>`
  ).join('');
  return `
    <div class="history-card risk-${risk}" data-id="${scan.id}">
      <div class="history-card-header">
        <span class="history-card-url">${escapeHtml(scan.target_url)}</span>
        <span class="history-risk-badge risk-${risk}">${risk}</span>
      </div>
      <div class="history-card-stats">
        <div class="history-stat stat-critical"><div class="history-stat-value">${scan.critical_count}</div><div class="history-stat-label">Crit</div></div>
        <div class="history-stat stat-high"><div class="history-stat-value">${scan.high_count}</div><div class="history-stat-label">High</div></div>
        <div class="history-stat stat-medium"><div class="history-stat-value">${scan.medium_count}</div><div class="history-stat-label">Med</div></div>
        <div class="history-stat stat-low"><div class="history-stat-value">${scan.low_count}</div><div class="history-stat-label">Low</div></div>
        <div class="history-stat stat-total"><div class="history-stat-value">${scan.total_findings}</div><div class="history-stat-label">Total</div></div>
      </div>
      <div class="history-card-footer">
        <div class="history-card-modules">${modules}</div>
        <div class="history-card-actions">
          <span class="history-card-date">${formatDate(scan.created_at)}</span>
          <button class="history-delete-btn" data-id="${scan.id}" title="Delete scan">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>
          </button>
        </div>
      </div>
    </div>
  `;
}

async function loadHistoryScanResults(scanId) {
  try {
    const detail = await window.auth.fetchScanDetail(scanId);
    if (!detail || !detail.result_json) {
      toast('No result data available for this scan.', 'info');
      return;
    }
    const results    = detail.result_json;
    const moduleList = detail.modules_run || Object.keys(results);
    const allFindings = buildFindingsList(results, moduleList);
    const counts = countSeverities(allFindings);

    const result = {
      url: detail.target_url,
      modules_requested: moduleList,
      modules_completed: moduleList,
      modules_failed: [],
      results,
      total_vulnerabilities: detail.total_findings ?? allFindings.length,
      critical_count: detail.critical_count ?? counts.critical,
      high_count:     detail.high_count ?? counts.high,
      medium_count:   detail.medium_count ?? counts.medium,
      low_count:      detail.low_count ?? counts.low,
      overall_risk:   detail.risk_level || topRisk(counts),
    };
    state.scanResults = result;
    state.allFindings = allFindings;
    renderResults(result);
    navigate('results');
    toast('Loaded historical scan results.', 'info');
  } catch (err) {
    toast('Could not load scan detail: ' + err.message, 'error');
  }
}

/* ══════════════════════════════════════════════
   Init
   ══════════════════════════════════════════════ */
function init() {
  window.app = { navigate, loadHistory, openCrawlerModal };

  // Nav links — guard history behind login
  $$('.nav-item[data-page]').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const page = link.dataset.page;
      if (page === 'history') {
        if (!window.auth?.isLoggedIn()) {
          window.openAuthModal?.('login');
          toast('Please sign in to view your scan history.', 'info');
          return;
        }
        navigate('history');
        loadHistory();
        return;
      }
      navigate(page);
    });
  });

  // Dashboard scan button
  $('#dashboard-scan-btn')?.addEventListener('click', () => navigate('scanner'));

  // Module cards click → go to scanner
  $$('.module-card').forEach(card => {
    card.addEventListener('click', () => navigate('scanner'));
  });

  // ── Wizard navigation ──
  // Step 1 → Step 2 (Next button)
  $('#wizard-next-1')?.addEventListener('click', () => {
    const url = $('#target-url').value.trim();
    if (!url) { toast('Please enter a target URL.', 'error'); $('#target-url').focus(); return; }
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      toast('URL must start with http:// or https://', 'error');
      return;
    }
    goToStep(2);
  });

  // Step 2 → Step 1 (Back)
  $('#wizard-back-2')?.addEventListener('click', () => goToStep(1));

  // Step 3 → Step 2 (Back — only allowed when not scanning)
  $('#wizard-back-3')?.addEventListener('click', () => {
    if (!state.scanning) goToStep(2);
  });

  // Stop Scan button (on step 3)
  $('#stop-scan-btn')?.addEventListener('click', async () => {
    if (!state.scanning || !state.currentJobId) return;
    
    const btn = $('#stop-scan-btn');
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner" style="border-width:2px;width:14px;height:14px;border-color:#ff2d55;border-right-color:transparent;margin-right:6px;display:inline-block;vertical-align:middle;"></span> Stopping...`;
    
    try {
      await window.api.stopScan(state.currentJobId);
      addLog(`[ ! ] Stop signal sent. Halting modules...`, 'warn');
    } catch (err) {
      toast('Failed to stop: ' + err.message, 'error');
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="6" width="12" height="12" rx="2"/></svg> Stop Scan`;
    }
  });

  // Launch Scan button (on step 2)
  $('#launch-scan-btn')?.addEventListener('click', launchScan);

  // Crawler toggle
  $$('input[name="crawler-toggle"]').forEach(radio => {
    radio.addEventListener('change', updateCrawlerControls);
  });
  updateCrawlerControls();

  // New scan button
  $('#new-scan-btn')?.addEventListener('click', () => navigate('scanner'));

  // History new scan button
  $('#history-new-scan-btn')?.addEventListener('click', () => navigate('scanner'));

  // Export buttons
  $('#download-report-btn')?.addEventListener('click', showDownloadModal);
  $('#copy-json-btn')?.addEventListener('click', copyJSON);
  // Download modal choices
  $('#download-json-choice')?.addEventListener('click', exportJSON);
  $('#download-pdf-choice')?.addEventListener('click', exportPDF);
  $('#download-modal-close')?.addEventListener('click', closeDownloadModal);
  $('#download-modal-overlay')?.addEventListener('click', (e) => {
    if (e.target === $('#download-modal-overlay')) closeDownloadModal();
  });

  // Select all modules
  const selectAll = $('#select-all');
  selectAll?.addEventListener('change', () => {
    $$('input[name="module"]').forEach(cb => cb.checked = selectAll.checked);
  });

  // Sync select-all when individual checkboxes change
  $$('input[name="module"]').forEach(cb => {
    cb.addEventListener('change', () => {
      const all     = $$('input[name="module"]');
      const checked = all.filter(c => c.checked);
      selectAll.checked       = checked.length === all.length;
      selectAll.indeterminate = checked.length > 0 && checked.length < all.length;
    });
  });

  // Findings filters
  $('#filter-severity')?.addEventListener('change', () => {
    renderFindingsTable(state.allFindings, $('#filter-severity').value, $('#filter-module').value);
  });
  $('#filter-module')?.addEventListener('change', () => {
    renderFindingsTable(state.allFindings, $('#filter-severity').value, $('#filter-module').value);
  });

  // Modal close
  $('#modal-close')?.addEventListener('click', closeFindingModal);
  $('#modal-overlay')?.addEventListener('click', (e) => {
    if (e.target === $('#modal-overlay')) closeFindingModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') closeFindingModal();
  });

  // Mobile menu
  $('#menu-btn')?.addEventListener('click', () => {
    $('#sidebar').classList.toggle('open');
  });

  // Initialise wizard at step 1
  goToStep(1);

  // Check server health
  checkServerStatus();
  setInterval(checkServerStatus, 30000);
}

document.addEventListener('DOMContentLoaded', init);
