/**
 * NetIDS — Client-Side Application Logic
 *
 * Modules:
 *   IDS.initLoginPage()        — Login + TOTP flow
 *   IDS.initDashboard()        — Live charts, stats, real-time WebSocket feed
 *   IDS.initAlertsPage()       — Paginated alert table, filters, modal triage
 *   IDS.initSearchPage()       — Packet search with cursor pagination
 *   IDS.initInvestigationPage()— Timeline, IP profile, TCP flow tabs
 *   IDS.initReportsPage()      — PDF/CSV download buttons
 *   IDS.initSettingsPage()     — IP blocking, blacklist/whitelist management
 *
 * Shared helpers: IDS.toast(), IDS.api(), IDS.formatDate(), IDS.severityBadge()
 */

const IDS = (() => {
  'use strict';

  /* ========================================================================
     SHARED UTILITIES
     ====================================================================== */

  /** Authenticated API fetch. Adds Authorization header if JWT stored. */
  async function api(path, options = {}) {
    const token = localStorage.getItem('ids_access_token');
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    };

    try {
      const res = await fetch(path, { ...options, headers });
      if (res.status === 401) {
        // Attempt silent token refresh
        const refreshed = await _refreshToken();
        if (refreshed) {
          // Retry once with new token
          headers.Authorization = `Bearer ${localStorage.getItem('ids_access_token')}`;
          return fetch(path, { ...options, headers });
        }
        _redirectToLogin();
      }
      return res;
    } catch (err) {
      console.error('[IDS.api]', err);
      throw err;
    }
  }

  async function _refreshToken() {
    const refresh = localStorage.getItem('ids_refresh_token');
    if (!refresh) return false;
    try {
      const res = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refresh }),
      });
      if (!res.ok) { _clearTokens(); return false; }
      const data = await res.json();
      localStorage.setItem('ids_access_token', data.access_token);
      return true;
    } catch { return false; }
  }

  function _clearTokens() {
    localStorage.removeItem('ids_access_token');
    localStorage.removeItem('ids_refresh_token');
  }

  function _redirectToLogin() {
    _clearTokens();
    window.location.href = '/auth/login';
  }

  /** Show a toast notification */
  function toast(message, type = 'info', durationMs = 4000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
    const el = document.createElement('div');
    el.className = `toast toast--${type}`;
    el.innerHTML = `
      <span class="toast-icon">${icons[type] ?? 'ℹ'}</span>
      <span class="toast-msg">${_esc(message)}</span>
    `;
    container.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transform = 'translateX(20px)';
      el.style.transition = 'all 0.3s ease';
      setTimeout(() => el.remove(), 320);
    }, durationMs);
  }

  /** ISO → human-readable relative time */
  function formatDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    const now = new Date();
    const diff = Math.floor((now - d) / 1000);
    if (diff < 60)   return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400)return `${Math.floor(diff / 3600)}h ago`;
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  /** HTML escape */
  function _esc(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  /** Severity badge HTML */
  function severityBadge(severity) {
    const s = (severity || '').toLowerCase();
    return `<span class="severity-badge severity-${s}">${_esc(severity || 'N/A')}</span>`;
  }

  /** Status badge HTML */
  function statusBadge(status) {
    const s = (status || '').toLowerCase();
    const label = s.replace(/_/g, ' ');
    return `<span class="status-badge status-${s}">${_esc(label || 'unknown')}</span>`;
  }

  /** Format number with commas */
  function fmt(n) {
    if (n == null || isNaN(n)) return '—';
    return Number(n).toLocaleString();
  }

  /** Sidebar toggle for mobile */
  function _initSidebarToggle() {
    const btn = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    if (btn && sidebar) {
      btn.addEventListener('click', () => sidebar.classList.toggle('open'));
      document.addEventListener('click', (e) => {
        if (!sidebar.contains(e.target) && !btn.contains(e.target)) {
          sidebar.classList.remove('open');
        }
      });
    }
  }

  /* ========================================================================
     LOGIN PAGE
     ====================================================================== */

  function initLoginPage() {
    const loginForm  = document.getElementById('login-form');
    const totpForm   = document.getElementById('totp-form');
    const totpSection= document.getElementById('totp-section');
    const formError  = document.getElementById('form-error');
    const loginBtn   = document.getElementById('login-btn');
    const totpBtn    = document.getElementById('totp-btn');
    const togglePwd  = document.getElementById('toggle-password');
    const passwordEl = document.getElementById('password');

    let _preAuthToken = null;

    function showError(msg) {
      formError.textContent = msg;
      formError.hidden = false;
    }

    function hideError() { formError.hidden = true; }

    function setLoading(btn, loading) {
      const text    = btn.querySelector('.btn-text');
      const spinner = btn.querySelector('.btn-spinner');
      btn.disabled = loading;
      text?.classList.toggle('hidden', loading);
      spinner?.classList.toggle('hidden', !loading);
    }

    // Password visibility toggle
    if (togglePwd && passwordEl) {
      togglePwd.addEventListener('click', () => {
        const isText = passwordEl.type === 'text';
        passwordEl.type = isText ? 'password' : 'text';
      });
    }

    // Step 1 — credentials
    if (loginForm) {
      loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideError();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;

        if (!username || !password) { showError('Username and password are required.'); return; }

        setLoading(loginBtn, true);
        try {
          const res  = await fetch('/api/v1/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password }),
          });
          const data = await res.json();

          if (!res.ok) { showError(data.error || 'Login failed.'); return; }

          if (data.requires_2fa) {
            _preAuthToken = data.pre_auth_token;
            loginForm.classList.add('hidden');
            totpSection.classList.remove('hidden');
            document.getElementById('totp-code')?.focus();
          } else {
            // Direct login (no 2FA)
            localStorage.setItem('ids_access_token',  data.access_token);
            localStorage.setItem('ids_refresh_token', data.refresh_token);
            window.location.href = '/dashboard';
          }
        } catch {
          showError('Network error — please try again.');
        } finally {
          setLoading(loginBtn, false);
        }
      });
    }

    // Step 2 — TOTP
    if (totpForm) {
      totpForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        hideError();
        const code = document.getElementById('totp-code').value.trim();

        if (!code || code.length !== 6) { showError('Enter the 6-digit code from your authenticator.'); return; }

        setLoading(totpBtn, true);
        try {
          const res  = await fetch('/api/v1/auth/verify-2fa', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pre_auth_token: _preAuthToken, totp_code: code }),
          });
          const data = await res.json();

          if (!res.ok) { showError(data.error || '2FA verification failed.'); return; }

          localStorage.setItem('ids_access_token',  data.access_token);
          localStorage.setItem('ids_refresh_token', data.refresh_token);
          window.location.href = '/dashboard';
        } catch {
          showError('Network error — please try again.');
        } finally {
          setLoading(totpBtn, false);
        }
      });
    }
  }

  /* ========================================================================
     DASHBOARD
     ====================================================================== */

  function initDashboard() {
    _initSidebarToggle();
    _initStatusBadge();

    let trafficChart   = null;
    let protocolChart  = null;
    let socket         = null;

    const trafficData  = { labels: [], pps: [], bps: [] };
    const MAX_POINTS   = 60;

    // ── Stats Cards ──────────────────────────────────────────────────────
    async function loadStats() {
      try {
        const res  = await api('/api/v1/packets/stats');
        if (!res.ok) return;
        const data = await res.json();

        _setText('pps-value',           fmt(data.packets_per_second));
        _setText('active-alerts-value', fmt(data.active_alerts ?? 0));
        _setText('critical-value',      fmt(data.critical_count  ?? 0));
        _setText('blocked-value',       fmt(data.blocked_ips     ?? 0));

        // Update alert badge in nav
        const badge = document.getElementById('alert-badge');
        if (badge) {
          const count = data.active_alerts ?? 0;
          badge.textContent = count;
          badge.dataset.count = count;
          badge.style.display = count > 0 ? 'inline-block' : 'none';
        }
      } catch (e) {
        console.warn('[dashboard] loadStats error', e);
      }
    }

    // ── Traffic Chart ─────────────────────────────────────────────────────
    function initTrafficChart() {
      const canvas = document.getElementById('traffic-chart');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');

      const gradient = ctx.createLinearGradient(0, 0, 0, 200);
      gradient.addColorStop(0,   'hsla(220, 90%, 62%, 0.25)');
      gradient.addColorStop(1,   'hsla(220, 90%, 62%, 0.00)');

      trafficChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: trafficData.labels,
          datasets: [{
            label: 'Packets/s',
            data: trafficData.pps,
            borderColor: 'hsl(220, 90%, 62%)',
            backgroundColor: gradient,
            borderWidth: 2,
            pointRadius: 0,
            tension: 0.4,
            fill: true,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 300 },
          interaction: { mode: 'index', intersect: false },
          plugins: {
            legend: { display: false },
            tooltip: {
              backgroundColor: 'hsl(225, 18%, 13%)',
              titleColor: 'hsl(220, 30%, 93%)',
              bodyColor:  'hsl(220, 15%, 60%)',
              borderColor:'hsl(220, 30%, 60%, 0.16)',
              borderWidth: 1,
              padding: 10,
            },
          },
          scales: {
            x: {
              grid: { color: 'hsla(220, 30%, 60%, 0.07)' },
              ticks: { color: 'hsl(220, 15%, 45%)', maxTicksLimit: 8, font: { size: 11 } },
            },
            y: {
              grid: { color: 'hsla(220, 30%, 60%, 0.07)' },
              ticks: { color: 'hsl(220, 15%, 45%)', font: { size: 11 } },
              beginAtZero: true,
            },
          },
        },
      });
    }

    // ── Protocol Doughnut ─────────────────────────────────────────────────
    function initProtocolChart() {
      const canvas = document.getElementById('protocol-chart');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');

      protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['TCP', 'UDP', 'ICMP', 'Other'],
          datasets: [{
            data: [0, 0, 0, 0],
            backgroundColor: [
              'hsl(220, 90%, 62%)',
              'hsl(148, 65%, 50%)',
              'hsl(38,  95%, 58%)',
              'hsl(270, 70%, 65%)',
            ],
            borderWidth: 0,
            hoverOffset: 6,
          }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '70%',
          plugins: {
            legend: {
              position: 'right',
              labels: { color: 'hsl(220, 15%, 60%)', font: { size: 11 }, boxWidth: 10, padding: 14 },
            },
            tooltip: {
              backgroundColor: 'hsl(225, 18%, 13%)',
              titleColor: 'hsl(220, 30%, 93%)',
              bodyColor:  'hsl(220, 15%, 60%)',
              borderColor:'hsla(220, 30%, 60%, 0.16)',
              borderWidth: 1,
            },
          },
        },
      });
    }

    // ── Protocol stats from API ────────────────────────────────────────────
    async function loadProtocolStats() {
      try {
        const res = await api('/api/v1/packets/protocols');
        if (!res.ok) return;
        const data = await res.json();
        if (!protocolChart) return;

        const labels = Object.keys(data.protocols || {});
        const values = Object.values(data.protocols || {});
        if (labels.length) {
          protocolChart.data.labels = labels;
          protocolChart.data.datasets[0].data = values;
          protocolChart.update('none');
        }
      } catch (e) { console.warn('[dashboard] protocol stats error', e); }
    }

    // Push a data point to the traffic chart
    function pushTrafficPoint(pps) {
      const now = new Date();
      const label = `${now.getHours().toString().padStart(2,'0')}:${now.getMinutes().toString().padStart(2,'0')}:${now.getSeconds().toString().padStart(2,'0')}`;

      trafficData.labels.push(label);
      trafficData.pps.push(pps);

      if (trafficData.labels.length > MAX_POINTS) {
        trafficData.labels.shift();
        trafficData.pps.shift();
      }

      if (trafficChart) {
        trafficChart.data.labels = trafficData.labels;
        trafficChart.data.datasets[0].data = trafficData.pps;
        trafficChart.update('none');
      }
    }

    // ── Recent Alerts Feed ────────────────────────────────────────────────
    async function loadAlertFeed() {
      try {
        const res  = await api('/api/v1/alerts?limit=8&status=new,acknowledged,investigating');
        if (!res.ok) return;
        const data = await res.json();
        const feed = document.getElementById('alert-feed');
        const empty= document.getElementById('feed-empty');
        if (!feed) return;

        const items = data.alerts || [];
        if (items.length === 0) {
          if (empty) empty.hidden = false;
          return;
        }
        if (empty) empty.hidden = true;

        // Remove existing feed items (keep the empty placeholder in DOM)
        feed.querySelectorAll('.feed-item').forEach(el => el.remove());

        items.forEach(a => {
          const sev = (a.severity || 'low').toLowerCase();
          const div = document.createElement('div');
          div.className = 'feed-item';
          div.innerHTML = `
            <div class="feed-dot feed-dot--${sev}"></div>
            <div class="feed-content">
              <div class="feed-title">${_esc(a.title || 'Unknown Alert')}</div>
              <div class="feed-meta">${_esc(a.source_ip || '—')} · ${formatDate(a.created_at)}</div>
            </div>
            ${severityBadge(a.severity)}
          `;
          feed.appendChild(div);
        });
      } catch (e) { console.warn('[dashboard] alert feed error', e); }
    }

    // ── Campaigns ─────────────────────────────────────────────────────────
    async function loadCampaigns() {
      try {
        const res  = await api('/api/v1/alerts/campaigns');
        if (!res.ok) return;
        const data = await res.json();
        const list = document.getElementById('campaign-list');
        if (!list) return;

        const campaigns = data.campaigns || [];
        if (campaigns.length === 0) {
          list.innerHTML = '<div class="feed-empty">No active campaigns</div>';
          return;
        }

        list.innerHTML = campaigns.slice(0, 5).map(c => `
          <div class="campaign-item">
            <div class="campaign-count">${c.alert_count || 0}</div>
            <div style="flex:1;min-width:0;">
              <div style="font-weight:600;font-size:0.83rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${_esc(c.source_ip || '—')}</div>
              <div style="font-size:0.72rem;color:var(--text-muted);">${_esc(c.attack_type || 'Unknown')} · ${formatDate(c.last_seen)}</div>
            </div>
            ${severityBadge(c.severity)}
          </div>
        `).join('');
      } catch (e) { console.warn('[dashboard] campaigns error', e); }
    }

    // ── WebSocket (real-time) ──────────────────────────────────────────────
    function initSocket() {
      if (typeof io === 'undefined') return;
      try {
        socket = io('/alerts', { transports: ['websocket', 'polling'] });

        socket.on('connect', () => {
          _setStatus(true);
          console.log('[IDS] Socket connected');
        });

        socket.on('disconnect', () => {
          _setStatus(false);
          console.warn('[IDS] Socket disconnected');
        });

        socket.on('new_alert', (alert) => {
          toast(`🚨 ${alert.severity?.toUpperCase()}: ${alert.title}`, 'error', 6000);
          loadAlertFeed();
          loadStats();
        });

        socket.on('traffic_stats_update', (data) => {
          pushTrafficPoint(data.packets_per_second ?? 0);
          _setText('pps-value', fmt(data.packets_per_second));
        });
      } catch (e) { console.warn('[IDS] Socket init failed', e); }
    }

    function _setStatus(online) {
      const dot   = document.getElementById('status-dot');
      const label = document.getElementById('status-label');
      if (!dot || !label) return;
      dot.className   = `status-dot ${online ? 'status-dot--active' : 'status-dot--error'}`;
      label.textContent = online ? 'Live' : 'Offline';
    }

    // Poll stats every 5 s (fallback when socket isn't pushing)
    let _pollInterval = null;

    async function startPolling() {
      await loadStats();
      await loadProtocolStats();
      await loadAlertFeed();
      await loadCampaigns();

      // Push initial traffic point from stat
      try {
        const r = await api('/api/v1/packets/stats');
        if (r.ok) {
          const d = await r.json();
          pushTrafficPoint(d.packets_per_second ?? 0);
        }
      } catch {}

      _pollInterval = setInterval(async () => {
        await loadStats();
        const r = await api('/api/v1/packets/stats');
        if (r.ok) {
          const d = await r.json();
          pushTrafficPoint(d.packets_per_second ?? 0);
        }
      }, 5000);

      setInterval(loadProtocolStats, 30000);
      setInterval(loadAlertFeed,     15000);
      setInterval(loadCampaigns,     20000);
    }

    // Init
    initTrafficChart();
    initProtocolChart();
    initSocket();
    startPolling();
  }

  /* ========================================================================
     ALERTS PAGE
     ====================================================================== */

  function initAlertsPage() {
    _initSidebarToggle();
    _initStatusBadge();

    let _currentPage = 1;
    let _totalAlerts = 0;
    const PAGE_SIZE  = 20;

    const tbody      = document.getElementById('alerts-tbody');
    const countLabel = document.getElementById('alert-count-label');
    const pagination = document.getElementById('alerts-pagination');
    const backdrop   = document.getElementById('alert-modal-backdrop');
    const modalBody  = document.getElementById('modal-body');
    const modalTitle = document.getElementById('modal-title');
    const statusSel  = document.getElementById('modal-status-select');
    const statusBtn  = document.getElementById('modal-status-btn');

    let _openAlertId = null;

    function buildQuery() {
      const params = new URLSearchParams();
      const severity= document.getElementById('filter-severity')?.value;
      const status  = document.getElementById('filter-status')?.value;
      const hours   = document.getElementById('filter-hours')?.value;
      if (severity) params.set('severity', severity);
      if (status)   params.set('status',   status);
      if (hours)    params.set('hours',    hours);
      params.set('page',  _currentPage);
      params.set('limit', PAGE_SIZE);
      return params.toString();
    }

    async function loadAlerts() {
      tbody.innerHTML = `<tr><td colspan="6" class="table-empty skeleton" style="height:48px;"></td></tr>`.repeat(5);

      try {
        const res  = await api(`/api/v1/alerts?${buildQuery()}`);
        if (!res.ok) { toast('Failed to load alerts', 'error'); return; }
        const data = await res.json();

        _totalAlerts = data.total || 0;
        const alerts = data.alerts || [];

        if (countLabel) countLabel.textContent = `${fmt(_totalAlerts)} alert${_totalAlerts !== 1 ? 's' : ''} found`;

        tbody.innerHTML = alerts.length === 0
          ? `<tr><td colspan="6" class="table-empty">No alerts match the current filters.</td></tr>`
          : alerts.map(a => `
            <tr class="clickable-row" data-alert-id="${_esc(a.id)}" style="cursor:pointer;">
              <td>${severityBadge(a.severity)}</td>
              <td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${_esc(a.title)}</td>
              <td>${statusBadge(a.status)}</td>
              <td style="color:var(--text-secondary);font-size:0.8rem;">${formatDate(a.created_at)}</td>
              <td style="color:var(--text-secondary);font-size:0.8rem;">${_esc(a.assigned_to || '—')}</td>
              <td>
                <button class="btn btn-sm btn-secondary" data-action="view" data-alert-id="${_esc(a.id)}">View</button>
              </td>
            </tr>
          `).join('');

        // Row click
        tbody.querySelectorAll('.clickable-row').forEach(row => {
          row.addEventListener('click', (e) => {
            if (e.target.closest('button')) return;
            openAlertModal(row.dataset.alertId);
          });
        });

        tbody.querySelectorAll('[data-action="view"]').forEach(btn => {
          btn.addEventListener('click', (e) => {
            e.stopPropagation();
            openAlertModal(btn.dataset.alertId);
          });
        });

        renderPagination();
      } catch (e) {
        tbody.innerHTML = `<tr><td colspan="6" class="table-empty text-danger">Error loading alerts.</td></tr>`;
        console.error('[alerts]', e);
      }
    }

    function renderPagination() {
      if (!pagination) return;
      const totalPages = Math.ceil(_totalAlerts / PAGE_SIZE);
      if (totalPages <= 1) { pagination.innerHTML = ''; return; }

      let html = '';
      if (_currentPage > 1) {
        html += `<button class="btn btn-ghost btn-sm" data-page="${_currentPage - 1}">← Prev</button>`;
      }
      const start = Math.max(1, _currentPage - 2);
      const end   = Math.min(totalPages, _currentPage + 2);
      for (let i = start; i <= end; i++) {
        html += `<button class="btn btn-sm ${i === _currentPage ? 'btn-primary' : 'btn-ghost'}" data-page="${i}">${i}</button>`;
      }
      if (_currentPage < totalPages) {
        html += `<button class="btn btn-ghost btn-sm" data-page="${_currentPage + 1}">Next →</button>`;
      }
      pagination.innerHTML = html;
      pagination.querySelectorAll('[data-page]').forEach(btn => {
        btn.addEventListener('click', () => {
          _currentPage = parseInt(btn.dataset.page);
          loadAlerts();
        });
      });
    }

    async function openAlertModal(alertId) {
      _openAlertId = alertId;
      backdrop?.classList.remove('hidden');
      if (modalBody) modalBody.innerHTML = '<div class="skeleton" style="height:180px;border-radius:8px;"></div>';

      try {
        const res  = await api(`/api/v1/alerts/${alertId}`);
        if (!res.ok) { toast('Failed to load alert details', 'error'); return; }
        const a    = await res.json();

        if (modalTitle) modalTitle.textContent = a.title || 'Alert Details';
        if (modalBody)  modalBody.innerHTML = `
          <div class="detail-grid">
            <div class="detail-item"><div class="detail-key">Severity</div><div class="detail-val">${severityBadge(a.severity)}</div></div>
            <div class="detail-item"><div class="detail-key">Status</div><div class="detail-val">${statusBadge(a.status)}</div></div>
            <div class="detail-item"><div class="detail-key">Source IP</div><div class="detail-val">${_esc(a.source_ip || '—')}</div></div>
            <div class="detail-item"><div class="detail-key">Target IP</div><div class="detail-val">${_esc(a.target_ip || '—')}</div></div>
            <div class="detail-item"><div class="detail-key">Attack Type</div><div class="detail-val">${_esc(a.attack_type || '—')}</div></div>
            <div class="detail-item"><div class="detail-key">Created</div><div class="detail-val">${formatDate(a.created_at)}</div></div>
          </div>
          ${a.threat_score != null ? `
          <div class="score-bar-wrapper">
            <div class="score-bar-label">
              <span>Threat Score</span>
              <span style="font-weight:700;color:var(--text-primary)">${a.threat_score}/100</span>
            </div>
            <div class="score-bar-track">
              <div class="score-bar-fill" style="width:${a.threat_score}%"></div>
            </div>
          </div>` : ''}
          <div style="background:var(--bg-elevated);border-radius:8px;padding:12px;font-size:0.85rem;color:var(--text-secondary);line-height:1.5;">
            ${_esc(a.message || 'No additional details.')}
          </div>
          ${(a.comments || []).length > 0 ? `
            <h4 style="margin-top:1rem;font-size:0.85rem;color:var(--text-secondary);">Comments</h4>
            ${a.comments.map(c => `
              <div style="background:var(--bg-elevated);border-radius:6px;padding:10px 12px;margin-top:6px;font-size:0.83rem;">
                <div style="font-weight:600;margin-bottom:3px;">${_esc(c.author || '—')} <span style="font-weight:400;color:var(--text-muted);">${formatDate(c.created_at)}</span></div>
                ${_esc(c.comment)}
              </div>
            `).join('')}
          ` : ''}
        `;
      } catch (e) {
        console.error('[modal]', e);
        toast('Error loading alert', 'error');
      }
    }

    function closeModal() {
      backdrop?.classList.add('hidden');
      _openAlertId = null;
    }

    // Modal status update
    statusBtn?.addEventListener('click', async () => {
      if (!_openAlertId || !statusSel?.value) return;
      try {
        const res = await api(`/api/v1/alerts/${_openAlertId}`, {
          method: 'PATCH',
          body: JSON.stringify({ status: statusSel.value }),
        });
        if (res.ok) {
          toast('Alert status updated', 'success');
          closeModal();
          loadAlerts();
        } else {
          const d = await res.json();
          toast(d.error || 'Update failed', 'error');
        }
      } catch { toast('Network error', 'error'); }
    });

    document.getElementById('modal-close')?.addEventListener('click', closeModal);
    backdrop?.addEventListener('click', (e) => { if (e.target === backdrop) closeModal(); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

    // Filter apply
    document.getElementById('filter-apply-btn')?.addEventListener('click', () => {
      _currentPage = 1;
      loadAlerts();
    });

    // Bulk acknowledge
    document.getElementById('bulk-ack-btn')?.addEventListener('click', async () => {
      try {
        const res = await api('/api/v1/alerts/bulk-acknowledge', { method: 'POST' });
        if (res.ok) {
          toast('All new alerts acknowledged', 'success');
          loadAlerts();
        }
      } catch { toast('Network error', 'error'); }
    });

    // Real-time new alert
    if (typeof io !== 'undefined') {
      try {
        const socket = io('/alerts', { transports: ['websocket', 'polling'] });
        socket.on('new_alert', () => {
          if (_currentPage === 1) loadAlerts();
        });
      } catch {}
    }

    loadAlerts();
  }

  /* ========================================================================
     SEARCH PAGE
     ====================================================================== */

  function initSearchPage() {
    _initSidebarToggle();
    _initStatusBadge();

    let _cursor     = null;
    let _lastParams = null;

    const tbody      = document.getElementById('search-tbody');
    const countLabel = document.getElementById('search-result-count');
    const loadMoreBtn= document.getElementById('load-more-btn');

    async function runSearch(append = false) {
      if (!append) {
        _cursor = null;
        tbody.innerHTML = `<tr><td colspan="7" class="table-empty skeleton" style="height:40px;"></td></tr>`.repeat(6);
      }

      const params = new URLSearchParams();
      const srcIp    = document.getElementById('s-src-ip')?.value.trim();
      const dstIp    = document.getElementById('s-dst-ip')?.value.trim();
      const protocol = document.getElementById('s-protocol')?.value;
      const dstPort  = document.getElementById('s-dst-port')?.value;
      const minSize  = document.getElementById('s-min-size')?.value;
      const maxSize  = document.getElementById('s-max-size')?.value;
      const start    = document.getElementById('s-start')?.value;
      const end      = document.getElementById('s-end')?.value;

      if (srcIp)    params.set('src_ip',   srcIp);
      if (dstIp)    params.set('dst_ip',   dstIp);
      if (protocol) params.set('protocol', protocol);
      if (dstPort)  params.set('dst_port', dstPort);
      if (minSize)  params.set('min_size', minSize);
      if (maxSize)  params.set('max_size', maxSize);
      if (start)    params.set('start',    start);
      if (end)      params.set('end',      end);
      if (_cursor)  params.set('cursor',   _cursor);

      params.set('limit', 50);
      _lastParams = new URLSearchParams(params);

      try {
        const res  = await api(`/api/v1/packets/search?${params}`);
        if (!res.ok) { toast('Search failed', 'error'); return; }
        const data = await res.json();

        const packets = data.packets || [];
        _cursor       = data.next_cursor || null;

        if (!append) {
          if (packets.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="table-empty">No packets found.</td></tr>`;
            if (countLabel) countLabel.textContent = '0 results';
            if (loadMoreBtn) loadMoreBtn.hidden = true;
            return;
          }
          tbody.innerHTML = '';
        }

        if (countLabel) countLabel.textContent = `${packets.length} packet${packets.length !== 1 ? 's' : ''} returned`;

        packets.forEach(p => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td class="cell-mono text-muted" style="font-size:0.78rem;">${p.id}</td>
            <td style="font-size:0.78rem;color:var(--text-secondary);white-space:nowrap;">${formatDate(p.captured_at)}</td>
            <td><span class="severity-badge severity-medium" style="text-transform:uppercase;font-size:0.7rem;">${_esc(p.protocol)}</span></td>
            <td class="cell-mono" style="font-size:0.82rem;">${_esc(p.src_ip)}:${p.src_port || '?'}</td>
            <td class="cell-mono" style="font-size:0.82rem;">${_esc(p.dst_ip)}:${p.dst_port || '?'}</td>
            <td style="font-size:0.82rem;color:var(--text-secondary);">${fmt(p.packet_size)}B</td>
            <td class="cell-mono" style="font-size:0.78rem;color:var(--text-muted);">${_esc(p.flags || '—')}</td>
          `;
          tbody.appendChild(tr);
        });

        if (loadMoreBtn) loadMoreBtn.hidden = !_cursor;
      } catch (e) {
        tbody.innerHTML = `<tr><td colspan="7" class="table-empty text-danger">Search error.</td></tr>`;
        console.error('[search]', e);
      }
    }

    document.getElementById('search-form')?.addEventListener('submit', (e) => {
      e.preventDefault();
      runSearch(false);
    });

    document.getElementById('search-reset-btn')?.addEventListener('click', () => {
      document.getElementById('search-form')?.reset();
      tbody.innerHTML = `<tr><td colspan="7" class="table-empty">Run a search to see results.</td></tr>`;
      if (countLabel) countLabel.textContent = 'Run a search to see results.';
      if (loadMoreBtn) loadMoreBtn.hidden = true;
    });

    loadMoreBtn?.addEventListener('click', () => runSearch(true));

    // CSV export link builder
    document.getElementById('export-csv-btn')?.addEventListener('click', (e) => {
      if (_lastParams) {
        const p = new URLSearchParams(_lastParams);
        p.delete('cursor');
        e.currentTarget.href = `/api/v1/reports/csv?${p}`;
      }
    });
  }

  /* ========================================================================
     INVESTIGATION PAGE
     ====================================================================== */

  function initInvestigationPage() {
    _initSidebarToggle();
    _initStatusBadge();

    // Tab system
    const tabs   = document.querySelectorAll('.tab-btn[role="tab"]');
    const panels = document.querySelectorAll('.tab-panel');

    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t  => { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
        panels.forEach(p => p.classList.add('hidden'));
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');
        const panelId = tab.getAttribute('aria-controls');
        document.getElementById(panelId)?.classList.remove('hidden');
      });
    });

    // ── Attack Timeline ───────────────────────────────────────────────────
    document.getElementById('timeline-load-btn')?.addEventListener('click', async () => {
      const eventId = document.getElementById('timeline-event-id')?.value.trim();
      const context = document.getElementById('timeline-context')?.value || 5;
      const container = document.getElementById('timeline-container');
      if (!eventId) { toast('Enter an attack event ID', 'warning'); return; }

      container.innerHTML = '<div class="skeleton" style="height:60px;border-radius:8px;margin-bottom:8px;"></div>'.repeat(4);

      try {
        const res  = await api(`/api/v1/investigation/timeline/${eventId}?context_minutes=${context}`);
        if (!res.ok) {
          const d = await res.json();
          container.innerHTML = `<p class="table-empty text-danger">${_esc(d.error || 'Failed to load timeline.')}</p>`;
          return;
        }
        const data   = await res.json();
        const events = data.events || [];

        if (events.length === 0) {
          container.innerHTML = '<p class="table-empty">No events found for this attack.</p>';
          return;
        }

        container.innerHTML = events.map(ev => `
          <div class="timeline-event">
            <div class="timeline-dot">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="4" fill="currentColor"/>
              </svg>
            </div>
            <div class="timeline-content">
              <div class="timeline-time">${_esc(ev.timestamp || '—')}</div>
              <div style="font-weight:600;font-size:0.85rem;">${_esc(ev.event_type || '—')}</div>
              <div style="font-size:0.82rem;color:var(--text-secondary);margin-top:3px;">
                ${_esc(ev.src_ip || '')} → ${_esc(ev.dst_ip || '')}
                ${ev.dst_port ? `:${ev.dst_port}` : ''} · ${_esc(ev.protocol || '')}
              </div>
            </div>
          </div>
        `).join('');
      } catch (e) {
        container.innerHTML = '<p class="table-empty text-danger">Network error loading timeline.</p>';
        console.error('[timeline]', e);
      }
    });

    // ── IP Profile ────────────────────────────────────────────────────────
    document.getElementById('ip-profile-btn')?.addEventListener('click', async () => {
      const ip     = document.getElementById('ip-profile-input')?.value.trim();
      const days   = document.getElementById('ip-profile-days')?.value || 30;
      const result = document.getElementById('ip-profile-result');
      if (!ip) { toast('Enter an IP address', 'warning'); return; }

      result.innerHTML = '<div class="skeleton" style="height:100px;border-radius:8px;"></div>';

      try {
        const res  = await api(`/api/v1/investigation/ip/${encodeURIComponent(ip)}?days=${days}`);
        if (!res.ok) {
          const d = await res.json();
          result.innerHTML = `<p class="table-empty text-danger">${_esc(d.error || 'Profile failed.')}</p>`;
          return;
        }
        const d = await res.json();

        result.innerHTML = `
          <div class="profile-header">
            <div>
              <div class="profile-ip">${_esc(d.ip_address)}</div>
              <div style="font-size:0.8rem;color:var(--text-muted);">${_esc(d.country || '—')} · ASN ${_esc(d.asn || '—')}</div>
            </div>
            <div style="margin-left:auto;">
              ${d.is_malicious ? '<span class="severity-badge severity-critical">Malicious</span>' : '<span class="severity-badge severity-low">Clean</span>'}
            </div>
          </div>
          <div class="detail-grid" style="margin-top:1rem;">
            <div class="detail-item"><div class="detail-key">Total Packets</div><div class="detail-val">${fmt(d.total_packets)}</div></div>
            <div class="detail-item"><div class="detail-key">Attack Events</div><div class="detail-val">${fmt(d.attack_count)}</div></div>
            <div class="detail-item"><div class="detail-key">Reputation Score</div><div class="detail-val">${d.reputation_score ?? '—'}/100</div></div>
            <div class="detail-item"><div class="detail-key">Last Seen</div><div class="detail-val">${formatDate(d.last_seen)}</div></div>
          </div>
          ${(d.recent_attacks || []).length > 0 ? `
            <h4 style="margin-top:1rem;font-size:0.8rem;color:var(--text-secondary);text-transform:uppercase;letter-spacing:0.05em;">Recent Attacks</h4>
            <div class="table-wrapper" style="margin-top:6px;">
              <table class="data-table">
                <thead><tr><th>Type</th><th>Severity</th><th>Date</th></tr></thead>
                <tbody>
                  ${d.recent_attacks.map(a => `
                    <tr>
                      <td>${_esc(a.attack_type)}</td>
                      <td>${severityBadge(a.severity)}</td>
                      <td style="color:var(--text-muted);font-size:0.78rem;">${formatDate(a.first_seen)}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          ` : ''}
        `;
      } catch (e) {
        result.innerHTML = '<p class="table-empty text-danger">Error fetching IP profile.</p>';
        console.error('[ip-profile]', e);
      }
    });

    // ── TCP Flow ──────────────────────────────────────────────────────────
    document.getElementById('flow-reconstruct-btn')?.addEventListener('click', async () => {
      const srcIp   = document.getElementById('flow-src-ip')?.value.trim();
      const dstIp   = document.getElementById('flow-dst-ip')?.value.trim();
      const dstPort = document.getElementById('flow-dst-port')?.value;
      const start   = document.getElementById('flow-start')?.value;
      const end     = document.getElementById('flow-end')?.value;
      const result  = document.getElementById('flow-result');

      if (!srcIp || !dstIp) { toast('Source and destination IPs are required', 'warning'); return; }

      result.innerHTML = '<div class="skeleton" style="height:80px;border-radius:8px;"></div>';

      const params = new URLSearchParams({ src_ip: srcIp, dst_ip: dstIp });
      if (dstPort) params.set('dst_port', dstPort);
      if (start)   params.set('start', start);
      if (end)     params.set('end', end);

      try {
        const res  = await api(`/api/v1/investigation/flow?${params}`);
        if (!res.ok) {
          const d = await res.json();
          result.innerHTML = `<p class="table-empty text-danger">${_esc(d.error || 'Flow reconstruction failed.')}</p>`;
          return;
        }
        const data   = await res.json();
        const packets = data.packets || [];

        if (packets.length === 0) {
          result.innerHTML = '<p class="table-empty">No flow packets found.</p>';
          return;
        }

        result.innerHTML = `
          <div style="font-size:0.78rem;color:var(--text-muted);margin-bottom:8px;">
            ${packets.length} packets reconstructed · ${formatDate(data.start_time)} → ${formatDate(data.end_time)}
          </div>
          <div style="max-height:320px;overflow-y:auto;background:var(--bg-elevated);border-radius:8px;border:1px solid var(--border-subtle);">
            ${packets.map(p => `
              <div class="flow-packet">
                <span style="color:var(--text-muted);min-width:80px;">${formatDate(p.captured_at)}</span>
                <span class="flow-arrow">${p.direction === 'client→server' ? '→' : '←'}</span>
                <span class="cell-mono">${_esc(p.src_ip)}:${p.src_port} → ${_esc(p.dst_ip)}:${p.dst_port}</span>
                <span style="color:var(--text-muted);margin-left:auto;">${fmt(p.packet_size)}B</span>
                <span style="color:var(--text-muted);margin-left:8px;">${_esc(p.flags || '')}</span>
              </div>
            `).join('')}
          </div>
          ${data.pcap_available ? `<a class="btn btn-secondary btn-sm mt-md" href="${_esc(data.pcap_url || '#')}">Download PCAP</a>` : ''}
        `;
      } catch (e) {
        result.innerHTML = '<p class="table-empty text-danger">Error reconstructing flow.</p>';
        console.error('[flow]', e);
      }
    });
  }

  /* ========================================================================
     REPORTS PAGE
     ====================================================================== */

  function initReportsPage() {
    _initSidebarToggle();
    _initStatusBadge();

    document.getElementById('download-pdf-btn')?.addEventListener('click', function(e) {
      e.preventDefault();
      const hours = document.getElementById('pdf-hours')?.value || 24;
      this.href = `/api/v1/reports/pdf?hours=${hours}`;
      // small delay then trigger
      setTimeout(() => { window.location.href = this.href; }, 100);
    });

    document.getElementById('download-csv-btn')?.addEventListener('click', function(e) {
      e.preventDefault();
      const srcIp    = document.getElementById('csv-src-ip')?.value.trim();
      const protocol = document.getElementById('csv-protocol')?.value;
      const params   = new URLSearchParams();
      if (srcIp)    params.set('src_ip', srcIp);
      if (protocol) params.set('protocol', protocol);
      window.location.href = `/api/v1/reports/csv?${params}`;
    });
  }

  /* ========================================================================
     SETTINGS PAGE
     ====================================================================== */

  function initSettingsPage() {
    _initSidebarToggle();
    _initStatusBadge();

    // ── Active Blocks ─────────────────────────────────────────────────────
    async function loadBlocks() {
      const tbody = document.getElementById('blocks-tbody');
      if (!tbody) return;
      try {
        const res  = await api('/api/v1/blocks/active');
        if (!res.ok) return;
        const data = await res.json();
        const blocks = data.blocks || [];
        tbody.innerHTML = blocks.length === 0
          ? '<tr><td colspan="5" class="table-empty">No active blocks.</td></tr>'
          : blocks.map(b => `
            <tr>
              <td class="cell-mono">${_esc(b.ip_address)}</td>
              <td>${_esc(b.block_type)}</td>
              <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-secondary);">${_esc(b.reason || '—')}</td>
              <td style="color:var(--text-muted);font-size:0.8rem;">${b.expires_at ? formatDate(b.expires_at) : 'Permanent'}</td>
              <td>
                <button class="btn btn-sm btn-ghost text-danger" data-action="unblock" data-ip="${_esc(b.ip_address)}">Unblock</button>
              </td>
            </tr>
          `).join('');

        // Unblock buttons
        tbody.querySelectorAll('[data-action="unblock"]').forEach(btn => {
          btn.addEventListener('click', async () => {
            await unblockIP(btn.dataset.ip);
            loadBlocks();
          });
        });
      } catch (e) { console.error('[blocks]', e); }
    }

    async function unblockIP(ip) {
      try {
        const res = await api('/api/v1/blocks/unblock', {
          method: 'POST',
          body: JSON.stringify({ ip_address: ip }),
        });
        if (res.ok) toast(`${ip} unblocked`, 'success');
        else {
          const d = await res.json();
          toast(d.error || 'Unblock failed', 'error');
        }
      } catch { toast('Network error', 'error'); }
    }

    // Block IP
    document.getElementById('block-ip-btn')?.addEventListener('click', async () => {
      const ip       = document.getElementById('block-ip-input')?.value.trim();
      const duration = document.getElementById('block-duration')?.value;
      if (!ip) { toast('Enter an IP address', 'warning'); return; }

      try {
        const body = { ip_address: ip, reason: 'Manual block via dashboard' };
        if (duration) body.duration_hours = parseInt(duration);

        const res = await api('/api/v1/blocks/block', {
          method: 'POST',
          body: JSON.stringify(body),
        });
        if (res.ok) {
          toast(`${ip} blocked`, 'success');
          document.getElementById('block-ip-input').value = '';
          document.getElementById('block-duration').value = '';
          loadBlocks();
        } else {
          const d = await res.json();
          toast(d.error || 'Block failed', 'error');
        }
      } catch { toast('Network error', 'error'); }
    });

    // Unblock from input
    document.getElementById('unblock-ip-btn')?.addEventListener('click', async () => {
      const ip = document.getElementById('unblock-ip-input')?.value.trim();
      if (!ip) { toast('Enter an IP address', 'warning'); return; }
      await unblockIP(ip);
      document.getElementById('unblock-ip-input').value = '';
      loadBlocks();
    });

    // ── Blacklist / Whitelist tabs ────────────────────────────────────────
    const tabBl = document.getElementById('tab-blacklist');
    const tabWl = document.getElementById('tab-whitelist');
    const panBl = document.getElementById('list-blacklist');
    const panWl = document.getElementById('list-whitelist');

    tabBl?.addEventListener('click', () => {
      tabBl.classList.add('active'); tabBl.setAttribute('aria-selected', 'true');
      tabWl?.classList.remove('active'); tabWl?.setAttribute('aria-selected', 'false');
      panBl?.classList.remove('hidden');
      panWl?.classList.add('hidden');
      loadBlacklist();
    });

    tabWl?.addEventListener('click', () => {
      tabWl.classList.add('active'); tabWl.setAttribute('aria-selected', 'true');
      tabBl?.classList.remove('active'); tabBl?.setAttribute('aria-selected', 'false');
      panWl?.classList.remove('hidden');
      panBl?.classList.add('hidden');
      loadWhitelist();
    });

    async function loadBlacklist() {
      const tbody = document.getElementById('blacklist-tbody');
      if (!tbody) return;
      try {
        const res  = await api('/api/v1/blocks/blacklist');
        if (!res.ok) return;
        const data = await res.json();
        const rows = data.blacklist || [];
        tbody.innerHTML = rows.length === 0
          ? '<tr><td colspan="5" class="table-empty">Blacklist is empty.</td></tr>'
          : rows.map(r => `
            <tr>
              <td class="cell-mono">${_esc(r.ip_address)}</td>
              <td style="color:var(--text-secondary);">${_esc(r.reason || '—')}</td>
              <td style="color:var(--text-muted);">${_esc(r.source || 'manual')}</td>
              <td style="color:var(--text-muted);font-size:0.8rem;">${formatDate(r.added_at)}</td>
              <td><button class="btn btn-sm btn-ghost text-danger" data-action="rm-bl" data-ip="${_esc(r.ip_address)}">Remove</button></td>
            </tr>
          `).join('');

        tbody.querySelectorAll('[data-action="rm-bl"]').forEach(btn => {
          btn.addEventListener('click', async () => {
            await api('/api/v1/blocks/blacklist/remove', {
              method: 'POST', body: JSON.stringify({ ip_address: btn.dataset.ip }),
            });
            toast(`${btn.dataset.ip} removed from blacklist`, 'success');
            loadBlacklist();
          });
        });
      } catch (e) { console.error('[blacklist]', e); }
    }

    async function loadWhitelist() {
      const tbody = document.getElementById('whitelist-tbody');
      if (!tbody) return;
      try {
        const res  = await api('/api/v1/blocks/whitelist');
        if (!res.ok) return;
        const data = await res.json();
        const rows = data.whitelist || [];
        tbody.innerHTML = rows.length === 0
          ? '<tr><td colspan="4" class="table-empty">Whitelist is empty.</td></tr>'
          : rows.map(r => `
            <tr>
              <td class="cell-mono">${_esc(r.ip_address)}</td>
              <td style="color:var(--text-secondary);">${_esc(r.description || '—')}</td>
              <td style="color:var(--text-muted);font-size:0.8rem;">${formatDate(r.added_at)}</td>
              <td><button class="btn btn-sm btn-ghost text-danger" data-action="rm-wl" data-ip="${_esc(r.ip_address)}">Remove</button></td>
            </tr>
          `).join('');

        tbody.querySelectorAll('[data-action="rm-wl"]').forEach(btn => {
          btn.addEventListener('click', async () => {
            await api('/api/v1/blocks/whitelist/remove', {
              method: 'POST', body: JSON.stringify({ ip_address: btn.dataset.ip }),
            });
            toast(`${btn.dataset.ip} removed from whitelist`, 'success');
            loadWhitelist();
          });
        });
      } catch (e) { console.error('[whitelist]', e); }
    }

    // Add to blacklist
    document.getElementById('add-blacklist-btn')?.addEventListener('click', async () => {
      const ip     = document.getElementById('add-blacklist-ip')?.value.trim();
      const reason = document.getElementById('add-blacklist-reason')?.value.trim();
      if (!ip) { toast('Enter an IP', 'warning'); return; }
      const res = await api('/api/v1/blocks/blacklist/add', {
        method: 'POST',
        body: JSON.stringify({ ip_address: ip, reason }),
      });
      if (res.ok) {
        toast(`${ip} added to blacklist`, 'success');
        document.getElementById('add-blacklist-ip').value = '';
        document.getElementById('add-blacklist-reason').value = '';
        loadBlacklist();
      } else {
        const d = await res.json();
        toast(d.error || 'Failed', 'error');
      }
    });

    // Add to whitelist
    document.getElementById('add-whitelist-btn')?.addEventListener('click', async () => {
      const ip   = document.getElementById('add-whitelist-ip')?.value.trim();
      const desc = document.getElementById('add-whitelist-desc')?.value.trim();
      if (!ip) { toast('Enter an IP', 'warning'); return; }
      const res = await api('/api/v1/blocks/whitelist/add', {
        method: 'POST',
        body: JSON.stringify({ ip_address: ip, description: desc }),
      });
      if (res.ok) {
        toast(`${ip} added to whitelist`, 'success');
        document.getElementById('add-whitelist-ip').value = '';
        document.getElementById('add-whitelist-desc').value = '';
        loadWhitelist();
      } else {
        const d = await res.json();
        toast(d.error || 'Failed', 'error');
      }
    });

    // Initial load
    loadBlocks();
    loadBlacklist();
  }

  /* ========================================================================
     PRIVATE HELPERS
     ====================================================================== */

  function _setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  }

  function _initStatusBadge() {
    // Show dot as active by default; socket disconnect will set to error
    const dot = document.getElementById('status-dot');
    if (dot) dot.className = 'status-dot status-dot--active';
  }

  /* ========================================================================
     PUBLIC API
     ====================================================================== */
  return {
    initLoginPage,
    initDashboard,
    initAlertsPage,
    initSearchPage,
    initInvestigationPage,
    initReportsPage,
    initSettingsPage,
    toast,
    api,
    formatDate,
    severityBadge,
    statusBadge,
  };
})();
