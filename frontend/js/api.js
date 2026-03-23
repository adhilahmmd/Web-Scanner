/**
 * WebSecuity API Client
 * Handles all communication with the FastAPI backend.
 */

class API {
  constructor(base = '') {
    this.base = base;
    this.POLL_INTERVAL = 2500; // ms
    this.MAX_POLLS = 120;      // 5 min max
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

  // ── Poll helper ──────────────────────────────
  /**
   * Poll a job endpoint until completion.
   * @param {Function} pollFn - async fn that returns { status, result }
   * @param {Function} onProgress - called with progress 0-100
   * @param {number} fakeProgressTarget - progress % to animate while waiting
   * @returns resolved job result
   */
  async poll(pollFn, onProgress = () => {}, fakeProgressTarget = 85) {
    let ticks = 0;
    let progress = 0;

    return new Promise((resolve, reject) => {
      const interval = setInterval(async () => {
        try {
          ticks++;
          // Fake incremental progress toward target
          if (progress < fakeProgressTarget) {
            progress = Math.min(fakeProgressTarget, progress + (fakeProgressTarget / 30));
            onProgress(Math.round(progress));
          }

          if (ticks > this.MAX_POLLS) {
            clearInterval(interval);
            reject(new Error('Scan timed out — please try again.'));
            return;
          }

          const data = await pollFn();
          if (data.status === 'completed') {
            clearInterval(interval);
            onProgress(100);
            resolve(data.result);
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
  async runModules(url, modules, timeout, crawlerConfig = {}, onProgress = () => {}) {
    onProgress(10);

    // 1. Kick off unified scan
    const job = await this.unifiedScanAsync(url, modules, timeout, crawlerConfig);
    const jobId = job.job_id;

    onProgress(25);

    // 2. Poll until complete
    const pollResult = await this.poll(
      () => this.getUnifiedScanResult(jobId),
      onProgress,
      88
    );

    onProgress(100);

    // 3. Return results keyed by module name
    const uResult = pollResult || {};
    return uResult;
  }
}

// Singleton
window.api = new API('');
