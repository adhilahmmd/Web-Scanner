/**
 * WebSecuity Auth Manager
 * Handles user registration, login, logout, and auth state.
 */

class AuthManager {
  constructor() {
    this.TOKEN_KEY = 'websecuity_token';
    this.USER_KEY = 'websecuity_user';
    this._listeners = [];
  }

  // ── Storage ────────────────────────────────────────────────────────────────
  getToken() {
    return localStorage.getItem(this.TOKEN_KEY);
  }

  getUser() {
    try {
      const raw = localStorage.getItem(this.USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  }

  isLoggedIn() {
    const token = this.getToken();
    if (!token) return false;
    // Decode JWT exp claim (no signature validation needed client-side)
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        if (payload.exp && payload.exp < Date.now() / 1000) {
          // Token has expired — auto-logout and report as not logged in
          this._clear();
          return false;
        }
      }
    } catch { /* malformed token or not a JWT — treat as present and valid */ }
    return true;
  }

  _store(token, user) {
    localStorage.setItem(this.TOKEN_KEY, token);
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
    this._emit('login', user);
  }

  _clear() {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
    this._emit('logout', null);
  }

  // ── Event emitter ──────────────────────────────────────────────────────────
  on(event, fn) {
    this._listeners.push({ event, fn });
  }

  _emit(event, data) {
    this._listeners.filter(l => l.event === event).forEach(l => l.fn(data));
  }

  // ── API calls ──────────────────────────────────────────────────────────────
  async _request(method, path, body = null) {
    const headers = { 'Content-Type': 'application/json' };
    const token = this.getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }
    return res.status === 204 ? null : res.json();
  }

  async register(username, email, password) {
    const data = await this._request('POST', '/api/users/register', { username, email, password });
    this._store(data.access_token, { id: data.user_id, username: data.username, email: data.email });
    return data;
  }

  async login(username, password) {
    const data = await this._request('POST', '/api/users/login', { username, password });
    this._store(data.access_token, { id: data.user_id, username: data.username, email: data.email });
    return data;
  }

  logout() {
    this._clear();
  }

  async fetchMe() {
    return this._request('GET', '/api/users/me');
  }

  async fetchHistory() {
    return this._request('GET', '/api/history');
  }

  async fetchScanDetail(id) {
    return this._request('GET', `/api/history/${id}`);
  }

  async deleteScan(id) {
    return this._request('DELETE', `/api/history/${id}`);
  }
}

// Singleton
window.auth = new AuthManager();


// ── Auth Modal Controller ──────────────────────────────────────────────────────
(function initAuthModal() {
  function handleAuthReady() {
    const modal = document.getElementById('auth-modal');
    const loginTab = document.getElementById('auth-tab-login');
    const registerTab = document.getElementById('auth-tab-register');
    const loginForm = document.getElementById('auth-login-form');
    const registerForm = document.getElementById('auth-register-form');
    const openAuthBtn = document.getElementById('open-auth-btn');
    const modalCloseAuth = document.getElementById('modal-close-auth');

    if (!modal) return;

    function showTab(tab) {
      const isLogin = tab === 'login';
      loginTab.classList.toggle('active', isLogin);
      registerTab.classList.toggle('active', !isLogin);
      loginForm.classList.toggle('hidden', !isLogin);
      registerForm.classList.toggle('hidden', isLogin);
    }

    loginTab?.addEventListener('click', () => showTab('login'));
    registerTab?.addEventListener('click', () => showTab('register'));

    function openModal(defaultTab = 'login') {
      modal.classList.remove('hidden');
      showTab(defaultTab);
      requestAnimationFrame(() => modal.classList.add('visible'));
    }

    function closeModal() {
      modal.classList.remove('visible');
      setTimeout(() => modal.classList.add('hidden'), 300);
    }

    openAuthBtn?.addEventListener('click', () => openModal('login'));
    modalCloseAuth?.addEventListener('click', closeModal);
    modal?.addEventListener('click', e => { if (e.target === modal) closeModal(); });

    // Login form submit
    loginForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = loginForm.querySelector('.auth-submit-btn');
      const errEl = loginForm.querySelector('.auth-error');
      const username = document.getElementById('login-username').value.trim();
      const password = document.getElementById('login-password').value;
      btn.disabled = true;
      btn.textContent = 'Signing in…';
      errEl.textContent = '';
      try {
        await window.auth.login(username, password);
        closeModal();
        window.showToast?.('Welcome back, ' + username + '!', 'success');
      } catch (err) {
        errEl.textContent = err.message;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Sign In';
      }
    });

    // Register form submit
    registerForm?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = registerForm.querySelector('.auth-submit-btn');
      const errEl = registerForm.querySelector('.auth-error');
      const username = document.getElementById('reg-username').value.trim();
      const email = document.getElementById('reg-email').value.trim();
      const password = document.getElementById('reg-password').value;
      const confirm = document.getElementById('reg-confirm').value;
      errEl.textContent = '';
      if (password !== confirm) { errEl.textContent = 'Passwords do not match.'; return; }
      btn.disabled = true;
      btn.textContent = 'Creating account…';
      try {
        await window.auth.register(username, email, password);
        closeModal();
        window.showToast?.('Account created! Welcome, ' + username + '!', 'success');
      } catch (err) {
        errEl.textContent = err.message;
      } finally {
        btn.disabled = false;
        btn.textContent = 'Create Account';
      }
    });

    // Auth state driven UI
    function updateSidebarUser(user) {
      const footerGuest = document.getElementById('sidebar-guest');
      const footerUser = document.getElementById('sidebar-user');
      const userInitials = document.getElementById('user-initials');
      const userName = document.getElementById('user-display-name');
      const userEmail = document.getElementById('user-display-email');
      const historyNavItem = document.getElementById('nav-history');

      if (user) {
        footerGuest?.classList.add('hidden');
        footerUser?.classList.remove('hidden');
        historyNavItem?.classList.remove('hidden');
        if (userInitials) userInitials.textContent = user.username.slice(0, 2).toUpperCase();
        if (userName) userName.textContent = user.username;
        if (userEmail) userEmail.textContent = user.email;
      } else {
        footerGuest?.classList.remove('hidden');
        footerUser?.classList.add('hidden');
        historyNavItem?.classList.add('hidden');
      }
    }

    // Initialize from stored state
    updateSidebarUser(window.auth.getUser());

    window.auth.on('login', (user) => updateSidebarUser(user));
    window.auth.on('logout', () => updateSidebarUser(null));

    // Logout button
    document.getElementById('logout-btn')?.addEventListener('click', () => {
      window.auth.logout();
      window.showToast?.('You have been signed out.', 'info');
      // Navigate away from history if on it
      window.app?.navigate('dashboard');
    });

    // Expose openModal globally
    window.openAuthModal = openModal;
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', handleAuthReady);
  } else {
    handleAuthReady();
  }
})();
