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

  // ── Crawler ──────────────────────────────────
  async crawlAsync(url, timeout = 15) {
    return this._fetch('POST', '/api/crawler/scan/async', { url, timeout, max_depth: 2, max_pages: 20 });
  }
  async getCrawlResult(jobId) {
    return this._fetch('GET', `/api/crawler/scan/${jobId}`);
  }

  // ── SQL Injection ────────────────────────────
  async sqliAsync(url, timeout = 15) {
    return this._fetch('POST', '/api/sqli/scan/async', { url, timeout });
  }
  async getSqliResult(jobId) {
    return this._fetch('GET', `/api/sqli/scan/${jobId}`);
  }

  // ── XSS ─────────────────────────────────────
  async xssAsync(url, timeout = 15) {
    return this._fetch('POST', '/api/xss/scan/async', {
      url, timeout, test_forms: true, test_headers: true, test_json: true
    });
  }
  async getXssResult(jobId) {
    return this._fetch('GET', `/api/xss/scan/${jobId}`);
  }

  // ── Broken Access Control ────────────────────
  async bacAsync(url, timeout = 15) {
    return this._fetch('POST', '/api/bac/scan/async', { url, timeout });
  }
  async getBacResult(jobId) {
    return this._fetch('GET', `/api/bac/scan/${jobId}`);
  }

  // ── Auth & Session ───────────────────────────
  async authAsync(url, timeout = 15) {
    return this._fetch('POST', '/api/auth/scan/async', {
      url, timeout, login_path: null, username_field: 'username', password_field: 'password'
    });
  }
  async getAuthResult(jobId) {
    return this._fetch('GET', `/api/auth/scan/${jobId}`);
  }

  // ── SSL/TLS ──────────────────────────────────
  async sslAsync(url, timeout = 15) {
    return this._fetch('POST', '/api/ssl/scan/async', { url, timeout });
  }
  async getSslResult(jobId) {
    return this._fetch('GET', `/api/ssl/scan/${jobId}`);
  }

  // ── HTTP Headers ─────────────────────────────
  async headersAsync(url, timeout = 15) {
    return this._fetch('POST', '/api/headers/scan/async', { url, timeout, follow_redirects: true });
  }
  async getHeadersResult(jobId) {
    return this._fetch('GET', `/api/headers/scan/${jobId}`);
  }

  // ── Unified Scan ─────────────────────────────
  async unifiedAsync(url, modules, timeout = 15) {
    return this._fetch('POST', '/api/scan/async', { url, modules, timeout });
  }
  async getUnifiedResult(jobId) {
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
   * Run multiple scanner modules individually with per-module polling.
   * Calls onModuleDone(moduleName, result) as each finishes.
   */
  async runModules(url, modules, timeout, onModuleDone = () => {}, onProgress = () => {}) {
    const total = modules.length;
    let done = 0;
    const results = {};

    const runOne = async (mod) => {
      let jobId;
      try {
        let job;
        if (mod === 'crawler') job = await this.crawlAsync(url, timeout);
        else if (mod === 'sqli') job = await this.sqliAsync(url, timeout);
        else if (mod === 'xss') job = await this.xssAsync(url, timeout);
        else if (mod === 'bac') job = await this.bacAsync(url, timeout);
        else if (mod === 'auth') job = await this.authAsync(url, timeout);
        else if (mod === 'ssl') job = await this.sslAsync(url, timeout);
        else if (mod === 'headers') job = await this.headersAsync(url, timeout);

        jobId = job.job_id;

        const pollFns = {
          crawler: (id) => this.getCrawlResult(id),
          sqli: (id) => this.getSqliResult(id),
          xss: (id) => this.getXssResult(id),
          bac: (id) => this.getBacResult(id),
          auth: (id) => this.getAuthResult(id),
          ssl: (id) => this.getSslResult(id),
          headers: (id) => this.getHeadersResult(id),
        };

        const result = await this.poll(() => pollFns[mod](jobId));
        results[mod] = result;
        done++;
        onProgress(Math.round((done / total) * 100));
        onModuleDone(mod, result, null);
      } catch (err) {
        results[mod] = { error: err.message };
        done++;
        onProgress(Math.round((done / total) * 100));
        onModuleDone(mod, null, err.message);
      }
    };

    await Promise.all(modules.map(runOne));
    return results;
  }
}

// Singleton
window.api = new API('');
