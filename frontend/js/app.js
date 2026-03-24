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
      (pct) => setProgress(pct)
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
      updateScanButton(false);
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
    updateScanButton(false);
    addLog(`[ ✗ ] Error: ${err.message}`, 'error');
    toast(`Scan failed: ${err.message}`, 'error');
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
  $('#download-json-btn').disabled = false;
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
    if (mod === 'crawler' && data?.pages_crawled !== undefined) extra = ` · ${data.pages_crawled} pages`;

    return `
      <div class="module-status-item">
        <span class="module-status-name">${MODULE_NAMES[mod] || mod}</span>
        <span class="module-status-badge ${badgeClass}">${badgeText}</span>
        <span class="module-status-count">${findings.length} findings${extra}</span>
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

function closeFindingModal() {
  $('#modal-overlay')?.classList.add('hidden');
  document.body.style.overflow = '';
}

/* ══════════════════════════════════════════════
   Export Helpers
   ══════════════════════════════════════════════ */
function exportJSON() {
  if (!state.scanResults) return;
  const json = JSON.stringify(state.scanResults, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url;
  a.download = `websecuity-scan-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Report downloaded!', 'success');
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
  window.app = { navigate, loadHistory };

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
  $('#download-json-btn')?.addEventListener('click', exportJSON);
  $('#copy-json-btn')?.addEventListener('click', copyJSON);

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
