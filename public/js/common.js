'use strict';

/**
 * Shared browser runtime for Secure Login.
 *
 * Everything here is deliberately dependency-free and CSP-safe: no inline
 * scripts, no inline event handlers, and no inline style mutations. Dynamic
 * values are written with textContent rather than innerHTML.
 */
(function () {
  document.documentElement.classList.add('js');

  const csrfState = {
    token: null,
    pending: null
  };

  const COMMON_PASSWORDS = new Set([
    'password', 'password1', 'password123', 'password1234', 'passw0rd',
    'p@ssw0rd', 'p@ssword123', 'qwerty123456', 'qwertyuiop', '123456789012',
    '1234567890123', 'letmein123456', 'welcome123456', 'admin123456',
    'iloveyou1234', 'monkey123456', 'dragon123456', 'football1234',
    'baseball1234', 'sunshine1234', 'princess1234', 'superman1234',
    'trustno1', 'changeme123', 'changeme1234', 'default12345',
    'administrator', 'administrator1', 'spring2024!', 'summer2024!',
    'autumn2024!', 'winter2024!', 'spring2025!', 'summer2025!',
    'autumn2025!', 'winter2025!', 'spring2026!', 'summer2026!',
    'companyname123', 'letmein!1234', 'welcome@1234', 'qwerty!@#123',
    'abc123456789', 'password!234', 'p@ssw0rd!234'
  ]);

  const SEQUENCE_PATTERN = /(0123456789|1234567890|abcdefghij|qwertyuiop)/i;

  class ApiError extends Error {
    constructor(message, details) {
      super(message);
      this.name = 'ApiError';
      const info = details || {};
      this.status = info.status || 0;
      this.code = info.code || 'NETWORK_ERROR';
      this.errors = info.errors || null;
      this.data = info.data || null;
    }
  }

  function apiUrl(path) {
    if (/^https?:\/\//i.test(path)) return path;
    if (path.startsWith('/api/')) return path;
    return `/api${path.startsWith('/') ? path : `/${path}`}`;
  }

  async function readResponseBody(response) {
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      try {
        return await response.json();
      } catch (error) {
        return null;
      }
    }
    try {
      return await response.text();
    } catch (error) {
      return null;
    }
  }

  async function fetchCsrfToken(force) {
    if (!force && csrfState.token) return csrfState.token;
    if (csrfState.pending) return csrfState.pending;

    csrfState.pending = (async () => {
      let response;
      try {
        response = await fetch('/api/csrf-token', {
          method: 'GET',
          credentials: 'same-origin',
          cache: 'no-store',
          headers: { Accept: 'application/json' }
        });
      } catch (error) {
        throw new ApiError(
          'Unable to reach the server. Check your connection and try again.',
          { code: 'NETWORK_ERROR' }
        );
      }

      const body = await readResponseBody(response);
      if (!response.ok || !body || !body.csrfToken) {
        throw new ApiError(
          'Could not establish a secure session. Refresh the page and try again.',
          { status: response.status, code: 'CSRF_FETCH_FAILED', data: body }
        );
      }

      csrfState.token = body.csrfToken;
      return csrfState.token;
    })();

    try {
      return await csrfState.pending;
    } finally {
      csrfState.pending = null;
    }
  }

  async function sendRequest(url, options, token) {
    const method = String(options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');

    let body = options.body;
    if (body !== undefined && body !== null && !(body instanceof FormData)) {
      if (typeof body !== 'string') {
        headers.set('Content-Type', 'application/json');
        body = JSON.stringify(body);
      } else if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
      }
    }

    if (token) headers.set('X-CSRF-Token', token);

    let response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: method === 'GET' || method === 'HEAD' ? undefined : body,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'follow'
      });
    } catch (error) {
      throw new ApiError(
        'Unable to reach the server. Check your connection and try again.',
        { code: 'NETWORK_ERROR' }
      );
    }

    const data = await readResponseBody(response);

    if (
      response.status === 403 &&
      data &&
      data.code === 'CSRF_INVALID' &&
      options.retry !== false
    ) {
      csrfState.token = data.csrfToken || null;
      const freshToken = data.csrfToken || (await fetchCsrfToken(true));
      return sendRequest(url, { ...options, retry: false }, freshToken);
    }

    if (!response.ok) {
      const fallback =
        response.status === 429
          ? 'Too many requests. Please wait a moment and try again.'
          : 'The request could not be completed. Please try again.';
      throw new ApiError(
        data && data.message ? data.message : fallback,
        {
          status: response.status,
          code: data && data.code ? data.code : 'REQUEST_FAILED',
          errors: data && data.errors ? data.errors : null,
          data
        }
      );
    }

    return data;
  }

  async function api(path, options) {
    const settings = options || {};
    const method = String(settings.method || 'GET').toUpperCase();
    const needsToken = !['GET', 'HEAD', 'OPTIONS'].includes(method);
    const token = needsToken ? await fetchCsrfToken(false) : null;
    return sendRequest(apiUrl(path), { ...settings, method }, token);
  }

  function setCsrfToken(token) {
    csrfState.token = token || null;
  }

  function getCsrfToken() {
    return fetchCsrfToken(false);
  }

  /* ----------------------------------------------------------------------
   * Toasts
   * -------------------------------------------------------------------- */
  function toastRegion() {
    let region = document.querySelector('.toast-region');
    if (!region) {
      region = document.createElement('div');
      region.className = 'toast-region';
      region.setAttribute('role', 'status');
      region.setAttribute('aria-live', 'polite');
      document.body.append(region);
    }
    return region;
  }

  function dismissToast(element) {
    if (!element || element.classList.contains('is-leaving')) return;
    element.classList.add('is-leaving');
    window.setTimeout(() => element.remove(), 220);
  }

  function toast(message, type, duration) {
    const kind = ['success', 'error', 'info'].includes(type) ? type : 'info';
    const region = toastRegion();
    const element = document.createElement('div');
    element.className = `toast toast-${kind}`;
    element.setAttribute('role', kind === 'error' ? 'alert' : 'status');

    const icon = document.createElement('span');
    icon.className = 'toast-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = kind === 'success' ? '\u2713' : kind === 'error' ? '!' : 'i';

    const copy = document.createElement('span');
    copy.textContent = message;

    element.append(icon, copy);
    region.append(element);
    window.setTimeout(() => dismissToast(element), duration || 4800);
    return element;
  }

  /* ----------------------------------------------------------------------
   * Form helpers
   * -------------------------------------------------------------------- */
  function fieldFor(form, name) {
    if (!form || !form.elements) return null;
    const control = form.elements.namedItem(name);
    if (!control) return null;
    if (control instanceof RadioNodeList) return control[0] ? control[0].closest('.field') : null;
    return control.closest('.field');
  }

  function clearFieldErrors(form) {
    if (!form) return;
    form.querySelectorAll('.field.has-error').forEach((field) => {
      field.classList.remove('has-error');
      const error = field.querySelector('.field-error');
      if (error) error.remove();
      field.querySelectorAll('[aria-invalid]').forEach((control) => {
        control.removeAttribute('aria-invalid');
        const describedBy = control.getAttribute('aria-describedby');
        if (describedBy && describedBy.startsWith('field-error-')) {
          control.removeAttribute('aria-describedby');
        }
      });
    });
  }

  function setFieldError(form, name, message) {
    const field = fieldFor(form, name);
    if (!field) return null;

    const control = field.querySelector('input, select, textarea');
    field.classList.add('has-error');
    let error = field.querySelector('.field-error');
    if (!error) {
      error = document.createElement('p');
      error.className = 'field-error';
      error.id = `field-error-${name}`;
      field.append(error);
    }
    error.textContent = message;
    error.setAttribute('role', 'alert');

    if (control) {
      control.setAttribute('aria-invalid', 'true');
      control.setAttribute('aria-describedby', error.id);
    }
    return control;
  }

  function showFormAlert(form, message, type) {
    if (!form) return;
    let alert = form.querySelector('[data-form-alert]');
    if (!alert) {
      alert = document.createElement('div');
      alert.setAttribute('data-form-alert', '');
      alert.setAttribute('role', 'alert');
      form.prepend(alert);
    }
    alert.className = `alert alert-${type || 'error'}`;
    alert.textContent = message;
    alert.hidden = false;
  }

  function hideFormAlert(form) {
    if (!form) return;
    const alert = form.querySelector('[data-form-alert]');
    if (alert) {
      alert.hidden = true;
      alert.textContent = '';
    }
  }

  function applyApiErrors(form, error) {
    clearFieldErrors(form);
    hideFormAlert(form);

    if (error && error.errors && Object.keys(error.errors).length > 0) {
      let firstControl = null;
      Object.entries(error.errors).forEach(([name, message]) => {
        const control = setFieldError(form, name, message);
        if (!firstControl && control) firstControl = control;
      });
      if (firstControl) firstControl.focus();
      return;
    }

    showFormAlert(
      form,
      error && error.message
        ? error.message
        : 'Something went wrong. Please try again.',
      'error'
    );
  }

  function setBusy(button, busy, busyLabel) {
    if (!button) return;
    const spinner = button.querySelector('[data-spinner]');
    const label = button.querySelector('[data-btn-label]');

    if (busy) {
      if (!button.dataset.idleLabel && label) {
        button.dataset.idleLabel = label.textContent;
      }
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
      if (spinner) spinner.hidden = false;
      if (label) label.textContent = busyLabel || 'Working\u2026';
    } else {
      button.disabled = false;
      button.removeAttribute('aria-busy');
      if (spinner) spinner.hidden = true;
      if (label && button.dataset.idleLabel) {
        label.textContent = button.dataset.idleLabel;
      }
    }
  }

  /* ----------------------------------------------------------------------
   * Password visibility, strength and navigation
   * -------------------------------------------------------------------- */
  function initPasswordToggles(root) {
    const scope = root || document;
    scope.querySelectorAll('[data-password-toggle]').forEach((button) => {
      if (button.dataset.toggleReady === 'true') return;
      const targetId =
        button.getAttribute('data-password-toggle') ||
        button.getAttribute('aria-controls');
      const target = targetId ? document.getElementById(targetId) : null;
      if (!target) return;
      button.dataset.toggleReady = 'true';

      button.addEventListener('click', () => {
        const visible = target.type === 'password';
        target.type = visible ? 'text' : 'password';
        button.classList.toggle('is-visible', visible);
        button.setAttribute('aria-pressed', String(visible));
        button.setAttribute(
          'aria-label',
          visible ? 'Hide password' : 'Show password'
        );
      });
    });
  }

  function passwordByteLength(value) {
    if (typeof TextEncoder === 'function') {
      return new TextEncoder().encode(value).length;
    }
    return value.length;
  }

  function evaluatePassword(password, options) {
    const value = String(password || '');
    const settings = options || {};
    const username = String(settings.username || '').trim().toLowerCase();
    const email = String(settings.email || '').trim().toLowerCase();
    const localPart = email.split('@')[0] || '';
    const normalized = value.toLowerCase();

    const checks = {
      length:
        value.length >= 12 &&
        value.length <= 72 &&
        passwordByteLength(value) <= 72,
      upper: /[A-Z]/.test(value),
      lower: /[a-z]/.test(value),
      number: /[0-9]/.test(value),
      symbol: /[^A-Za-z0-9\s]/.test(value),
      noSpace: value.length > 0 && !/\s/.test(value),
      noPersonal:
        value.length > 0 &&
        !(username.length >= 3 && normalized.includes(username)) &&
        !(localPart.length >= 3 && normalized.includes(localPart)),
      notCommon: value.length > 0 && !COMMON_PASSWORDS.has(normalized),
      noSequence:
        value.length > 0 &&
        !/(.)\1{5,}/.test(value) &&
        !SEQUENCE_PATTERN.test(value)
    };

    let score = 0;
    if (checks.length) score += 1;
    if (checks.upper && checks.lower) score += 1;
    if (checks.number) score += 1;
    if (checks.symbol) score += 1;

    const labels = ['Too short', 'Weak', 'Fair', 'Good', 'Strong'];
    const valid =
      checks.length &&
      checks.upper &&
      checks.lower &&
      checks.number &&
      checks.symbol &&
      checks.noSpace &&
      checks.noPersonal &&
      checks.notCommon &&
      checks.noSequence;

    return { score, label: labels[score], checks, valid };
  }

  function initPasswordStrength(config) {
    const input = config && config.input;
    if (!input) return null;

    const meter = config.meter || document.querySelector('[data-strength-meter]');
    const valueLabel = config.value || document.querySelector('[data-strength-value]');
    const requirements = config.requirements
      ? Array.from(config.requirements)
      : Array.from(document.querySelectorAll('[data-requirement]'));

    function render() {
      const result = evaluatePassword(input.value, {
        username: config.username ? config.username.value : '',
        email: config.email ? config.email.value : ''
      });

      if (meter) meter.setAttribute('data-score', String(result.score));
      if (valueLabel) {
        valueLabel.textContent = result.label;
        valueLabel.setAttribute('data-score', String(result.score));
      }
      requirements.forEach((item) => {
        const key = item.getAttribute('data-requirement');
        item.classList.toggle('is-met', Boolean(result.checks[key]));
      });
      return result;
    }

    input.addEventListener('input', render);
    if (config.username) config.username.addEventListener('input', render);
    if (config.email) config.email.addEventListener('input', render);
    render();

    return { evaluate: render };
  }

  function initNav() {
    let backdrop = document.querySelector('.nav-backdrop');
    if (!backdrop) {
      backdrop = document.createElement('button');
      backdrop.type = 'button';
      backdrop.className = 'nav-backdrop';
      backdrop.setAttribute('aria-hidden', 'true');
      backdrop.hidden = true;
      document.body.append(backdrop);
      backdrop.addEventListener('click', () => {
        document.querySelectorAll('[data-nav-toggle]').forEach((btn) => {
          const t = document.getElementById(btn.getAttribute('aria-controls'));
          if (t && t.classList.contains('is-open')) {
            t.classList.remove('is-open');
            btn.setAttribute('aria-expanded', 'false');
          }
        });
        backdrop.setAttribute('hidden', '');
      });
    }

    document.querySelectorAll('[data-nav-toggle]').forEach((button) => {
      if (button.dataset.navReady === 'true') return;
      button.dataset.navReady = 'true';
      const target = document.getElementById(button.getAttribute('aria-controls'));
      if (!target) return;

      const close = () => {
        target.classList.remove('is-open');
        button.setAttribute('aria-expanded', 'false');
        backdrop.setAttribute('hidden', '');
      };

      const openPanel = () => {
        target.classList.add('is-open');
        button.setAttribute('aria-expanded', 'true');
        backdrop.removeAttribute('hidden');
      };

      button.addEventListener('click', (event) => {
        event.stopPropagation();
        const open = !target.classList.contains('is-open');
        if (open) openPanel(); else close();
      });

      target.addEventListener('click', (event) => {
        if (event.target.closest('a')) close();
      });

      document.addEventListener('click', (event) => {
        if (!target.classList.contains('is-open')) return;
        if (target.contains(event.target) || button.contains(event.target)) return;
        close();
      });

      document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape' && target.classList.contains('is-open')) {
          close();
          button.focus();
        }
      });

      window.addEventListener('resize', () => {
        if (window.innerWidth > 960) close();
      });
    });
  }

  function initReveals() {
    const items = Array.from(document.querySelectorAll('.reveal'));
    if (items.length === 0) return;

    if (!('IntersectionObserver' in window)) {
      items.forEach((item) => item.classList.add('is-visible'));
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add('is-visible');
          observer.unobserve(entry.target);
        });
      },
      { threshold: 0.12, rootMargin: '0px 0px -36px 0px' }
    );

    items.forEach((item) => observer.observe(item));
  }

  function initYear() {
    const year = String(new Date().getFullYear());
    document.querySelectorAll('[data-current-year]').forEach((element) => {
      element.textContent = year;
    });
  }

  /* ----------------------------------------------------------------------
   * Formatting and clipboard
   * -------------------------------------------------------------------- */
  function toDate(value) {
    if (!value) return null;
    const date = value instanceof Date ? value : new Date(value);
    return Number.isNaN(date.getTime()) ? null : date;
  }

  function formatDate(value) {
    const date = toDate(value);
    if (!date) return '\u2014';
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    }).format(date);
  }

  function formatDateTime(value) {
    const date = toDate(value);
    if (!date) return '\u2014';
    return new Intl.DateTimeFormat(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit'
    }).format(date);
  }

  function formatRelative(value) {
    const date = toDate(value);
    if (!date) return '\u2014';
    const seconds = Math.round((date.getTime() - Date.now()) / 1000);
    const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
    const units = [
      ['year', 31536000],
      ['month', 2592000],
      ['week', 604800],
      ['day', 86400],
      ['hour', 3600],
      ['minute', 60],
      ['second', 1]
    ];
    for (const [unit, size] of units) {
      if (Math.abs(seconds) >= size || unit === 'second') {
        return formatter.format(Math.round(seconds / size), unit);
      }
    }
    return '\u2014';
  }

  function initials(name) {
    const parts = String(name || '')
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    if (parts.length === 0) return 'SL';
    if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
    return `${parts[0][0]}${parts[parts.length - 1][0]}`.toUpperCase();
  }

  function firstName(name) {
    const parts = String(name || '')
      .trim()
      .split(/\s+/)
      .filter(Boolean);
    return parts.length > 0 ? parts[0] : 'there';
  }

  async function copyText(text) {
    const value = String(text || '');
    if (!value) return false;

    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(value);
        return true;
      } catch (error) {
        // Fall through to the legacy path.
      }
    }

    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', '');
    textarea.className = 'sr-only';
    document.body.append(textarea);
    textarea.select();
    let copied = false;
    try {
      copied = document.execCommand('copy');
    } catch (error) {
      copied = false;
    }
    textarea.remove();
    return copied;
  }

  function redirectToLogin(expired) {
    window.location.replace(expired ? '/login?expired=1' : '/login');
  }

  function init() {
    initNav();
    initPasswordToggles();
    initReveals();
    initYear();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

  window.SecureLogin = {
    ApiError,
    api,
    applyApiErrors,
    clearFieldErrors,
    copyText,
    evaluatePassword,
    firstName,
    formatDate,
    formatDateTime,
    formatRelative,
    getCsrfToken,
    hideFormAlert,
    initials,
    initPasswordStrength,
    initPasswordToggles,
    redirectToLogin,
    setBusy,
    setCsrfToken,
    setFieldError,
    showFormAlert,
    toast
  };
})();
