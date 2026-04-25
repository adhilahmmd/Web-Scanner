/**
 * WebSecuity API Client
 * Handles all communication with the FastAPI backend.
 */

class API {
  constructor(base = '') {
    this.base = base;
    this.POLL_INTERVAL = 800; // ms — fast enough to catch per-module progress
    this.MAX_POLLS = 450;     // 6 min max (450 × 800ms)
  }

  async _fetch(method, path, body = null) {
    const headers = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
    // Inject auth token if available
    const token = window.auth?.getToken?.();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(this.base + path, opts);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.json();
  }

  // ── Health ────────────────────────────────────
  async health() {
    return this._fetch('GET', '/health');
  }

  // ── History Save ───────────────────────────
  async saveScanHistory(scanResult) {
    return this._fetch('POST', '/api/history/save', scanResult);
  }

  // ── Unified Scan ─────────────────────────────
  async unifiedScanAsync(url, modules = [], timeout = 15, crawlerConfig = {}) {
    const payload = {
      url,
      modules,
      timeout: parseInt(timeout),
      use_crawler: crawlerConfig.use_crawler !== false,
      max_depth: crawlerConfig.max_depth || 2,
      max_pages: crawlerConfig.max_pages || 20,
      scan_all_links: crawlerConfig.scan_all_links !== false,
    };
    return this._fetch('POST', '/api/scan/async', payload);
  }

  async getUnifiedScanResult(jobId) {
    return this._fetch('GET', `/api/scan/${jobId}`);
  }

  // ── Stop Scan ────────────────────────────────
  async stopScan(jobId) {
    return this._fetch('POST', `/api/scan/${jobId}/stop`);
  }

  // ── Poll helper ──────────────────────────────
  /**
   * Poll a job endpoint until completion.
   * Progress is read directly from the backend `progress` field (0-100).
   * @param {Function} pollFn - async fn that returns { status, progress, result }
   * @param {Function} onProgress - called with the real backend progress 0-100
   * @returns resolved job result
   */
  async poll(pollFn, onProgress = () => {}, _unused = 85) {
    let ticks = 0;

    return new Promise((resolve, reject) => {
      const interval = setInterval(async () => {
        try {
          ticks++;

          if (ticks > this.MAX_POLLS) {
            clearInterval(interval);
            reject(new Error('Scan timed out — please try again.'));
            return;
          }

          const data = await pollFn();

          // Use real backend progress; floor at 10 so the bar never looks frozen
          const backendProgress = data.progress ?? 0;
          onProgress(Math.max(10, Math.min(99, backendProgress)));

          // Surface backend status message in the scan log if available
          if (data.status_message && this._lastMsg !== data.status_message) {
            this._lastMsg = data.status_message;
            if (typeof addLog === 'function') addLog(`[ … ] ${data.status_message}`, 'muted');
          }

          if (data.status === 'completed') {
            clearInterval(interval);
            onProgress(100);
            resolve(data.result);
          } else if (data.status === 'cancelled') {
            clearInterval(interval);
            reject(new Error(data.error || 'Scan was manually stopped.'));
          } else if (data.status === 'failed') {
            clearInterval(interval);
            reject(new Error(data.error || 'Scan failed.'));
          }
        } catch (err) {
          clearInterval(interval);
          reject(err);
        }
      }, this.POLL_INTERVAL);
    });
  }

  /**
   * Run multiple scanner modules via the Unified DAST Pipeline.
   * @param {string} url - Target URL
   * @param {string[]} modules - List of module IDs
   * @param {number} timeout - Per-module timeout in seconds
   * @param {object} crawlerConfig - { use_crawler, max_depth, max_pages, scan_all_links }
   * @param {Function} onProgress - Called with progress percentage 0-100
   * @returns {object} Map of moduleName -> moduleResult
   */
  async runModules(url, modules, timeout, crawlerConfig = {}, onProgress = () => {}, onJobCreated = null) {
    // Show a small initial progress while the job is being created
    onProgress(5);

    // 1. Kick off unified scan
    const job = await this.unifiedScanAsync(url, modules, timeout, crawlerConfig);
    const jobId = job.job_id;
    if (onJobCreated) onJobCreated(jobId);

    // 2. Poll until complete — progress comes entirely from the backend
    const pollResult = await this.poll(
      () => this.getUnifiedScanResult(jobId),
      onProgress
    );

    onProgress(100);

    // 3. Return the unified result object
    const uResult = pollResult || {};
    return uResult;
  }
}

// Singleton
window.api = new API('');
