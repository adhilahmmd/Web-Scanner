/**
 * WebSecuity – Main Application Logic
 * SPA navigation, scan flow, results rendering, modal, toast, filters.
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

/* ══════════════════════════════════════════════
   App State
   ══════════════════════════════════════════════ */
const state = {
  currentPage: 'dashboard',
  scanResults: null,   // last completed scan
  allFindings: [],     // flat list of all findings {module, ...finding}
  scanning: false,
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
   Scan Flow
   ══════════════════════════════════════════════ */
async function launchScan() {
  const urlInput = $('#target-url');
  const url = urlInput.value.trim();

  if (!url) { toast('Please enter a target URL.', 'error'); urlInput.focus(); return; }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    toast('URL must start with http:// or https://', 'error');
    return;
  }

  const modules = $$('input[name="module"]:checked').map(cb => cb.value);
  if (modules.length === 0) {
    toast('Select at least one scanner module.', 'error');
    return;
  }

  const timeout = parseInt($('#scan-timeout').value) || 15;

  // Switch UI to scanning mode
  state.scanning = true;
  updateScanButton(true);
  showScanActive(url);

  // Reset log
  $('#scan-log').innerHTML = '';
  addLog(`[ * ] Starting scan on: ${url}`, 'info');
  addLog(`[ * ] Modules: ${modules.join(', ')}`, 'info');
  addLog(`[ * ] Timeout: ${timeout}s per module`, 'muted');
  addLog('', 'muted');

  const moduleResults = {};
  const completed = [];
  const failed = [];

  try {
    await window.api.runModules(
      url,
      modules,
      timeout,
      // onModuleDone
      (modName, result, err) => {
        if (err) {
          addLog(`[ ✗ ] ${MODULE_NAMES[modName] || modName}: FAILED — ${err}`, 'error');
          moduleResults[modName] = { error: err };
          failed.push(modName);
        } else {
          const count = (result?.findings || []).length;
          const severity = result?.summary?.risk_level || result?.summary?.grade || '—';
          addLog(`[ ✓ ] ${MODULE_NAMES[modName] || modName}: ${count} finding(s) | Risk: ${severity}`, 'success');
          moduleResults[modName] = result;
          completed.push(modName);
        }
      },
      // onProgress
      (pct) => setProgress(pct)
    );

    addLog('', 'muted');
    addLog('[ ✓ ] Scan complete! Rendering results...', 'success');
    setProgress(100);

    // Build combined result
    const allFindings = buildFindingsList(moduleResults, modules);
    const counts = countSeverities(allFindings);
    const risk = topRisk(counts);

    const result = {
      url,
      modules_requested: modules,
      modules_completed: completed,
      modules_failed: failed,
      results: moduleResults,
      total_vulnerabilities: allFindings.length,
      critical_count: counts.critical,
      high_count: counts.high,
      medium_count: counts.medium,
      low_count: counts.low,
      overall_risk: risk,
    };

    state.scanResults = result;
    state.allFindings = allFindings;

    // Update dashboard stats
    updateDashboardStats(result);

    // Show results after small delay
    setTimeout(() => {
      state.scanning = false;
      updateScanButton(false);
      renderResults(result);
      navigate('results');
      toast('Scan complete!', 'success');
    }, 800);

  } catch (err) {
    state.scanning = false;
    updateScanButton(false);
    addLog(`[ ✗ ] Error: ${err.message}`, 'error');
    toast(`Scan failed: ${err.message}`, 'error');
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
    const findings = data.findings || [];
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
  $('#stat-last-critical').textContent = result.critical_count;
  $('#stat-last-high').textContent = result.high_count;
  $('#stat-last-total').textContent = result.total_vulnerabilities;
}

/* ══════════════════════════════════════════════
   Results Rendering
   ══════════════════════════════════════════════ */
function renderResults(result) {
  // Show content, hide empty state
  $('#results-empty').classList.add('hidden');
  $('#results-content').classList.remove('hidden');
  $('#copy-json-btn').disabled = false;
  $('#download-json-btn').disabled = false;
  $('#results-subtitle').textContent = `Scanned: ${result.url} — ${result.total_vulnerabilities} findings`;

  // Risk badge
  const risk = result.overall_risk || 'info';
  const riskBadge = $('#risk-badge');
  riskBadge.textContent = risk.toUpperCase();
  riskBadge.className = `risk-badge risk-${risk}`;
  $('#risk-url').textContent = result.url;

  // Counts
  $('#count-critical').textContent = result.critical_count || 0;
  $('#count-high').textContent = result.high_count || 0;
  $('#count-medium').textContent = result.medium_count || 0;
  $('#count-low').textContent = result.low_count || 0;
  $('#count-total').textContent = result.total_vulnerabilities || 0;

  // Donut chart
  const chart = new DonutChart('severity-chart', 'chart-legend');
  const counts = countSeverities(state.allFindings);
  chart.draw([
    { label: 'Critical', value: counts.critical, color: SEV_COLORS.critical },
    { label: 'High',     value: counts.high,     color: SEV_COLORS.high },
    { label: 'Medium',   value: counts.medium,   color: SEV_COLORS.medium },
    { label: 'Low',      value: counts.low,      color: SEV_COLORS.low },
    { label: 'Info',     value: counts.info,     color: SEV_COLORS.info },
  ]);

  // Module status list
  renderModuleStatus(result);

  // Findings table
  renderFindingsTable(state.allFindings);
}

function renderModuleStatus(result) {
  const container = $('#modules-status-list');
  if (!container) return;

  const mods = result.modules_requested || [];
  container.innerHTML = mods.map(mod => {
    const data = result.results?.[mod];
    const failed = result.modules_failed?.includes(mod);
    const findings = data?.findings || [];
    const criticalCount = findings.filter(f => (f.severity || '').toLowerCase() === 'critical').length;
    const hasFindings = findings.length > 0;

    let badgeClass = 'badge-info';
    let badgeText = 'No findings';
    if (failed) { badgeClass = 'badge-error'; badgeText = 'Error'; }
    else if (criticalCount > 0) { badgeClass = 'badge-error'; badgeText = 'Critical'; }
    else if (hasFindings) { badgeClass = 'badge-warn'; badgeText = 'Findings'; }
    else if (data && !failed) { badgeClass = 'badge-ok'; badgeText = 'Clean'; }

    // Special info for some modules
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

  // Sort by severity
  const sevIdx = (s) => SEV_ORDER.indexOf((s || '').toLowerCase());
  filtered.sort((a, b) => sevIdx(a.severity) - sevIdx(b.severity));

  tbody.innerHTML = filtered.map((f, i) => {
    const sev = (f.severity || 'info').toLowerCase();
    const mod = f._module || '';
    const desc = f.description || f.evidence || '—';
    const param = f.parameter || f.header_name || f.check_type || '—';

    return `
      <tr data-idx="${i}">
        <td><span class="sev-badge sev-badge-${sev}">${sev}</span></td>
        <td><span class="module-badge">${MODULE_NAMES[mod] || mod}</span></td>
        <td class="cell-desc">${escapeHtml(desc.substring(0, 120))}${desc.length > 120 ? '...' : ''}</td>
        <td class="cell-param" title="${escapeHtml(param)}">${escapeHtml(param)}</td>
        <td><button class="details-btn" data-idx="${i}">View</button></td>
      </tr>
    `;
  }).join('');

  // Attach detail view listeners
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
  const body = $('#modal-body');
  if (!modal || !finding) return;

  const sev = (finding.severity || 'info').toLowerCase();
  title.textContent = finding.description || finding.check_type || 'Finding Detail';

  const rows = [
    { label: 'Severity', value: `<span class="sev-badge sev-badge-${sev}">${sev}</span>` },
    { label: 'Module', value: `<span class="module-badge">${MODULE_NAMES[finding._module] || finding._module || '—'}</span>` },
    finding.parameter ? { label: 'Parameter / Field', value: `<div class="detail-value monospace">${escapeHtml(finding.parameter)}</div>`, raw: true } : null,
    finding.header_name ? { label: 'Header', value: `<div class="detail-value monospace">${escapeHtml(finding.header_name)}</div>`, raw: true } : null,
    finding.check_type ? { label: 'Check Type', value: finding.check_type } : null,
    finding.xss_type ? { label: 'XSS Type', value: finding.xss_type } : null,
    finding.injection_point ? { label: 'Injection Point', value: finding.injection_point } : null,
    finding.payload ? { label: 'Payload Used', value: `<div class="detail-value monospace">${escapeHtml(finding.payload)}</div>`, raw: true } : null,
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
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
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

/* ══════════════════════════════════════════════
   Init
   ══════════════════════════════════════════════ */
function init() {
  // Expose navigate for inline events
  window.app = { navigate };

  // Nav links
  $$('.nav-item[data-page]').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      navigate(link.dataset.page);
    });
  });

  // Dashboard scan button
  $('#dashboard-scan-btn')?.addEventListener('click', () => navigate('scanner'));

  // Module cards click → go to scanner
  $$('.module-card').forEach(card => {
    card.addEventListener('click', () => navigate('scanner'));
  });

  // Launch scan button
  $('#launch-scan-btn')?.addEventListener('click', launchScan);

  // New scan button
  $('#new-scan-btn')?.addEventListener('click', () => navigate('scanner'));

  // Export buttons
  $('#download-json-btn')?.addEventListener('click', exportJSON);
  $('#copy-json-btn')?.addEventListener('click', copyJSON);

  // Select all modules
  const selectAll = $('#select-all');
  selectAll?.addEventListener('change', () => {
    $$('input[name="module"]').forEach(cb => cb.checked = selectAll.checked);
    $$('.module-checkbox').forEach(cb => {
      if (selectAll.checked) cb.style.borderColor = 'rgba(0, 212, 255, 0.4)';
    });
  });

  // Sync select-all when individual checkboxes change
  $$('input[name="module"]').forEach(cb => {
    cb.addEventListener('change', () => {
      const all = $$('input[name="module"]');
      const checked = all.filter(c => c.checked);
      selectAll.checked = checked.length === all.length;
      selectAll.indeterminate = checked.length > 0 && checked.length < all.length;
    });
  });

  // Findings filters
  $('#filter-severity')?.addEventListener('change', () => {
    renderFindingsTable(
      state.allFindings,
      $('#filter-severity').value,
      $('#filter-module').value
    );
  });
  $('#filter-module')?.addEventListener('change', () => {
    renderFindingsTable(
      state.allFindings,
      $('#filter-severity').value,
      $('#filter-module').value
    );
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

  // Check server health
  checkServerStatus();
  setInterval(checkServerStatus, 30000);
}

document.addEventListener('DOMContentLoaded', init);
