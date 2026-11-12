'use strict';

/**
 * Security console controller.
 *
 * Loads the authenticated account snapshot, renders it with textContent only,
 * and drives the two-factor enrollment, rotation and disable flows. Every
 * state-changing request goes through the shared CSRF-aware API client.
 */
(function () {
  const {
    api,
    clearFieldErrors,
    copyText,
    firstName,
    formatDate,
    formatDateTime,
    formatRelative,
    initials,
    redirectToLogin,
    setBusy,
    setCsrfToken,
    setFieldError,
    toast
  } = window.SecureLogin;

  const main = document.querySelector('[data-app-main]');
  if (!main) return;

  const els = {
    main,
    loadError: document.querySelector('[data-load-error]'),
    userAvatar: document.querySelector('[data-user-avatar]'),
    userName: document.querySelector('[data-user-name]'),
    userHandle: document.querySelector('[data-user-handle]'),
    firstName: document.querySelector('[data-first-name]'),
    accountName: document.querySelector('[data-account-name]'),
    accountEmail: document.querySelector('[data-account-email]'),
    accountUsername: document.querySelector('[data-account-username]'),
    accountCreated: document.querySelector('[data-account-created]'),
    accountLastLogin: document.querySelector('[data-account-last-login]'),
    sessionExpiry: document.querySelector('[data-session-expiry]'),
    statStatus: document.querySelector('[data-stat-status]'),
    stat2fa: document.querySelector('[data-stat-2fa]'),
    stat2faMeta: document.querySelector('[data-stat-2fa-meta]'),
    statMember: document.querySelector('[data-stat-member]'),
    statLastLogin: document.querySelector('[data-stat-last-login]'),
    statLastLoginMeta: document.querySelector('[data-stat-last-login-meta]'),
    twoFactorState: document.querySelector('[data-2fa-state]'),
    twoFactorTitle: document.querySelector('[data-2fa-title]'),
    twoFactorCopy: document.querySelector('[data-2fa-copy]'),
    twoFactorBadge: document.querySelector('[data-2fa-badge]'),
    startWrap: document.querySelector('[data-2fa-start-wrap]'),
    startButton: document.querySelector('[data-2fa-start]'),
    setup: document.querySelector('[data-2fa-setup]'),
    qr: document.querySelector('[data-2fa-qr]'),
    secret: document.querySelector('[data-2fa-secret]'),
    copySecret: document.querySelector('[data-2fa-copy-secret]'),
    cancelSetup: document.querySelector('[data-2fa-cancel]'),
    enableForm: document.querySelector('[data-2fa-enable-form]'),
    enableCode: document.querySelector('[data-2fa-enable-code]'),
    enableFeedback: document.querySelector('[data-enable-feedback]'),
    enabledActions: document.querySelector('[data-2fa-enabled-actions]'),
    disableForm: document.querySelector('[data-2fa-disable-form]'),
    disablePassword: document.querySelector('[data-2fa-disable-password]'),
    disableCode: document.querySelector('[data-2fa-disable-code]'),
    disableFeedback: document.querySelector('[data-disable-feedback]'),
    recoveryForm: document.querySelector('[data-recovery-form]'),
    recoveryPassword: document.querySelector('[data-recovery-password]'),
    recoveryCode: document.querySelector('[data-recovery-code]'),
    recoveryFeedback: document.querySelector('[data-recovery-feedback]'),
    recoveryPanel: document.querySelector('[data-recovery-panel]'),
    recoveryCodes: document.querySelector('[data-recovery-codes]'),
    recoveryCopy: document.querySelector('[data-recovery-copy]'),
    recoveryDownload: document.querySelector('[data-recovery-download]'),
    recoveryClose: document.querySelector('[data-recovery-close]'),
    eventList: document.querySelector('[data-event-list]'),
    logoutButtons: document.querySelectorAll('[data-logout]')
  };

  const state = {
    user: null,
    session: null,
    recoveryCodes: []
  };

  const EVENT_META = {
    account_created: { label: 'Account created', glyph: '+', tone: 'is-success' },
    login_success: { label: 'Successful sign-in', glyph: '\u2713', tone: 'is-success' },
    logout: { label: 'Signed out', glyph: '\u2190', tone: '' },
    account_locked: {
      label: 'Account temporarily locked after failed attempts',
      glyph: '!',
      tone: 'is-warning'
    },
    two_factor_enabled: {
      label: 'Two-factor authentication enabled',
      glyph: '2',
      tone: 'is-violet'
    },
    two_factor_disabled: {
      label: 'Two-factor authentication disabled',
      glyph: '2',
      tone: 'is-warning'
    },
    recovery_code_used: {
      label: 'Recovery code used to sign in',
      glyph: 'R',
      tone: 'is-warning'
    },
    recovery_codes_regenerated: {
      label: 'Recovery codes regenerated',
      glyph: 'R',
      tone: 'is-violet'
    }
  };

  /* ----------------------------------------------------------------------
   * Small DOM helpers
   * -------------------------------------------------------------------- */
  function setText(element, value) {
    if (element) element.textContent = value;
  }

  function showFeedback(element, message) {
    if (!element) return;
    element.textContent = message;
    element.hidden = false;
  }

  function hideFeedback(element) {
    if (!element) return;
    element.hidden = true;
    element.textContent = '';
  }

  function resetForm(form) {
    if (!form) return;
    form.reset();
    clearFieldErrors(form);
  }

  function formatCodeInput(input) {
    if (!input) return;
    input.addEventListener('input', () => {
      const raw = input.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
      if (/^[0-9]*$/.test(raw)) {
        input.value = raw.slice(0, 6);
        return;
      }
      const trimmed = raw.slice(0, 10);
      input.value =
        trimmed.length > 5 ? `${trimmed.slice(0, 5)}-${trimmed.slice(5)}` : trimmed;
    });
  }

  function handleActionError(form, feedback, error) {
    if (error && error.status === 401 && error.code === 'UNAUTHENTICATED') {
      redirectToLogin(true);
      return;
    }

    clearFieldErrors(form);
    hideFeedback(feedback);

    if (error && error.errors && Object.keys(error.errors).length > 0) {
      let firstControl = null;
      Object.entries(error.errors).forEach(([name, message]) => {
        const control = setFieldError(form, name, message);
        if (!firstControl && control) firstControl = control;
      });
      if (firstControl) firstControl.focus();
      return;
    }

    showFeedback(
      feedback,
      error && error.message
        ? error.message
        : 'Something went wrong. Please try again.'
    );
  }

  /* ----------------------------------------------------------------------
   * Rendering
   * -------------------------------------------------------------------- */
  function renderLoadError(error) {
    if (!els.loadError) return;
    els.loadError.textContent =
      error && error.message
        ? error.message
        : 'Could not load your account details. Refresh the page to try again.';
    els.loadError.hidden = false;
  }

  function renderIdentity() {
    const user = state.user;
    if (!user) return;

    setText(els.userAvatar, initials(user.fullName));
    setText(els.userName, user.fullName);
    setText(els.userHandle, `@${user.username}`);
    setText(els.firstName, firstName(user.fullName));
    setText(els.accountName, user.fullName);
    setText(els.accountEmail, user.email);
    setText(els.accountUsername, user.username);
    setText(els.accountCreated, formatDateTime(user.createdAt));
    setText(
      els.accountLastLogin,
      user.lastLoginAt ? formatDateTime(user.lastLoginAt) : 'No prior sign-in recorded'
    );

    setText(els.statStatus, 'Active');
    setText(els.statMember, formatDate(user.createdAt));
    setText(
      els.statLastLogin,
      user.lastLoginAt ? formatRelative(user.lastLoginAt) : 'First session'
    );
    setText(
      els.statLastLoginMeta,
      user.lastLoginAt ? formatDateTime(user.lastLoginAt) : 'No earlier sign-in recorded'
    );
  }

  function renderSession() {
    if (!els.sessionExpiry) return;
    const expiresAt = state.session && state.session.expiresAt;
    if (!expiresAt) {
      els.sessionExpiry.textContent = 'Expiration unavailable';
      els.sessionExpiry.removeAttribute('title');
      return;
    }
    els.sessionExpiry.textContent = `Expires ${formatRelative(expiresAt)}`;
    els.sessionExpiry.title = formatDateTime(expiresAt);
  }

  function renderTwoFactor() {
    const enabled = Boolean(state.user && state.user.twoFactorEnabled);

    if (els.twoFactorState) {
      els.twoFactorState.classList.toggle('is-enabled', enabled);
    }
    setText(
      els.twoFactorTitle,
      enabled ? 'Two-factor authentication is on' : 'Two-factor authentication is off'
    );
    setText(
      els.twoFactorCopy,
      enabled
        ? 'Sign-in requires a six-digit authenticator code or a single-use recovery code.'
        : 'Add a time-based one-time password as a second factor. Recovery codes are generated at enrollment.'
    );

    if (els.twoFactorBadge) {
      els.twoFactorBadge.className = enabled ? 'badge badge-green' : 'badge badge-amber';
      els.twoFactorBadge.textContent = enabled ? 'Enabled' : 'Off';
      els.twoFactorBadge.hidden = false;
    }

    setText(els.stat2fa, enabled ? 'Enabled' : 'Disabled');
    setText(
      els.stat2faMeta,
      enabled ? 'TOTP + recovery codes' : 'No second factor configured'
    );

    if (els.startWrap) els.startWrap.hidden = enabled;
    if (els.enabledActions) els.enabledActions.hidden = !enabled;

    if (!enabled) {
      hideSetup();
      hideRecoveryPanel();
    }
  }

  function renderEvents(events) {
    if (!els.eventList) return;
    els.eventList.replaceChildren();

    if (!Array.isArray(events) || events.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'empty-state';
      empty.textContent = 'No security activity recorded yet.';
      els.eventList.append(empty);
      return;
    }

    events.forEach((event) => {
      const meta = EVENT_META[event.type] || {
        label: String(event.type || 'Security event')
          .replace(/_/g, ' ')
          .replace(/^./, (character) => character.toUpperCase()),
        glyph: '\u00b7',
        tone: ''
      };

      const item = document.createElement('div');
      item.className = 'event-item';

      const dot = document.createElement('span');
      dot.className = `event-dot ${meta.tone}`.trim();
      dot.setAttribute('aria-hidden', 'true');
      dot.textContent = meta.glyph;

      const copy = document.createElement('span');
      copy.className = 'event-copy';

      const label = document.createElement('strong');
      label.textContent = meta.label;

      const time = document.createElement('span');
      time.textContent = `${formatDateTime(event.createdAt)} \u00b7 ${formatRelative(
        event.createdAt
      )}`;

      copy.append(label, time);
      item.append(dot, copy);
      els.eventList.append(item);
    });
  }

  function renderAll(data) {
    renderIdentity();
    renderSession();
    renderTwoFactor();
    renderEvents(data.securityEvents);
  }

  /* ----------------------------------------------------------------------
   * Recovery-code panel
   * -------------------------------------------------------------------- */
  function showRecoveryCodes(codes) {
    if (!Array.isArray(codes) || codes.length === 0) return;
    state.recoveryCodes = codes.slice();

    if (els.recoveryCodes) {
      els.recoveryCodes.replaceChildren();
      codes.forEach((code) => {
        const chip = document.createElement('span');
        chip.className = 'code-chip';
        chip.textContent = code;
        els.recoveryCodes.append(chip);
      });
    }

    if (els.recoveryPanel) els.recoveryPanel.hidden = false;
  }

  function hideRecoveryPanel() {
    state.recoveryCodes = [];
    if (els.recoveryCodes) els.recoveryCodes.replaceChildren();
    if (els.recoveryPanel) els.recoveryPanel.hidden = true;
  }

  function hideSetup() {
    if (els.setup) els.setup.hidden = true;
    if (els.qr) els.qr.removeAttribute('src');
    setText(els.secret, '');
    resetForm(els.enableForm);
    hideFeedback(els.enableFeedback);
  }

  /* ----------------------------------------------------------------------
   * Data loading
   * -------------------------------------------------------------------- */
  async function loadDashboard(options) {
    const silent = Boolean(options && options.silent);
    if (!silent) {
      els.main.classList.add('is-loading');
      if (els.loadError) els.loadError.hidden = true;
    }

    try {
      const data = await api('/dashboard');
      state.user = data.user;
      state.session = data.session;
      renderAll(data);
      if (els.loadError) els.loadError.hidden = true;
    } catch (error) {
      if (error.status === 401) {
        redirectToLogin(true);
        return;
      }
      if (!silent) renderLoadError(error);
    } finally {
      els.main.classList.remove('is-loading');
    }
  }

  /* ----------------------------------------------------------------------
   * Event wiring
   * -------------------------------------------------------------------- */
  formatCodeInput(els.enableCode);
  formatCodeInput(els.disableCode);
  formatCodeInput(els.recoveryCode);

  els.logoutButtons.forEach((button) => {
    button.addEventListener('click', async () => {
      if (button.disabled) return;
      setBusy(button, true, 'Signing out\u2026');
      try {
        await api('/auth/logout', { method: 'POST' });
        setCsrfToken(null);
        window.location.assign('/login?signedout=1');
      } catch (error) {
        setBusy(button, false);
        toast(
          error && error.message
            ? error.message
            : 'Could not sign out. Please try again.',
          'error'
        );
      }
    });
  });

  if (els.startButton) {
    els.startButton.addEventListener('click', async () => {
      if (els.startButton.disabled) return;
      setBusy(els.startButton, true, 'Generating\u2026');
      try {
        const data = await api('/2fa/setup', { method: 'POST' });
        if (els.qr) els.qr.src = data.qrCodeDataUrl;
        setText(els.secret, data.secret);
        resetForm(els.enableForm);
        hideFeedback(els.enableFeedback);
        if (els.setup) {
          els.setup.hidden = false;
          els.setup.scrollIntoView({ block: 'nearest' });
        }
        if (els.enableCode) els.enableCode.focus();
      } catch (error) {
        if (error.status === 401 && error.code === 'UNAUTHENTICATED') {
          redirectToLogin(true);
          return;
        }
        toast(
          error && error.message
            ? error.message
            : 'Could not start two-factor setup. Please try again.',
          'error'
        );
      } finally {
        setBusy(els.startButton, false);
      }
    });
  }

  if (els.copySecret) {
    els.copySecret.addEventListener('click', async () => {
      const secret = els.secret ? els.secret.textContent : '';
      if (!secret) return;
      const copied = await copyText(secret);
      toast(
        copied
          ? 'Setup key copied to the clipboard.'
          : 'Copy failed. Select the key and copy it manually.',
        copied ? 'success' : 'error'
      );
    });
  }

  if (els.cancelSetup) {
    els.cancelSetup.addEventListener('click', () => {
      hideSetup();
      toast('Two-factor setup cancelled.', 'info');
    });
  }

  if (els.enableForm) {
    els.enableForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = els.enableForm.querySelector('[data-submit]');
      if (button.disabled) return;

      clearFieldErrors(els.enableForm);
      hideFeedback(els.enableFeedback);

      const code = els.enableCode.value.trim();
      if (!/^\d{6}$/.test(code)) {
        const control = setFieldError(
          els.enableForm,
          'code',
          'Enter the current six-digit code from your authenticator app.'
        );
        if (control) control.focus();
        return;
      }

      setBusy(button, true, 'Enabling\u2026');
      try {
        const data = await api('/2fa/enable', {
          method: 'POST',
          body: { code }
        });

        state.user = { ...state.user, twoFactorEnabled: true };
        hideSetup();
        renderTwoFactor();
        showRecoveryCodes(data.recoveryCodes);
        toast(
          data.message ||
            'Two-factor authentication enabled. Save your recovery codes.',
          'success'
        );
        loadDashboard({ silent: true });
      } catch (error) {
        if (error.code === 'TWO_FACTOR_SETUP_EXPIRED') {
          hideSetup();
          toast(error.message, 'warning');
        } else {
          handleActionError(els.enableForm, els.enableFeedback, error);
        }
      } finally {
        setBusy(button, false);
      }
    });
  }

  function validateSensitiveAction(form, passwordInput, codeInput, feedback) {
    clearFieldErrors(form);
    hideFeedback(feedback);

    let firstControl = null;

    if (!passwordInput.value) {
      firstControl = setFieldError(form, 'password', 'Enter your current password.');
    }

    const code = codeInput.value.trim();
    if (!code) {
      const control = setFieldError(
        form,
        'code',
        'Enter a six-digit authenticator code or a recovery code.'
      );
      if (!firstControl) firstControl = control;
    } else if (
      !/^\d{6}$/.test(code) &&
      !/^[A-Z0-9]{5}-?[A-Z0-9]{5}$/i.test(code)
    ) {
      const control = setFieldError(
        form,
        'code',
        'Enter a six-digit code or a recovery code in the format ABCDE-23456.'
      );
      if (!firstControl) firstControl = control;
    }

    if (firstControl) {
      firstControl.focus();
      return false;
    }
    return true;
  }

  if (els.disableForm) {
    els.disableForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = els.disableForm.querySelector('[data-submit]');
      if (button.disabled) return;
      if (
        !validateSensitiveAction(
          els.disableForm,
          els.disablePassword,
          els.disableCode,
          els.disableFeedback
        )
      ) {
        return;
      }

      setBusy(button, true, 'Disabling\u2026');
      try {
        const data = await api('/2fa/disable', {
          method: 'POST',
          body: {
            password: els.disablePassword.value,
            code: els.disableCode.value.trim()
          }
        });

        state.user = { ...state.user, twoFactorEnabled: false };
        resetForm(els.disableForm);
        hideFeedback(els.disableFeedback);
        hideRecoveryPanel();
        renderTwoFactor();
        toast(data.message || 'Two-factor authentication disabled.', 'success');
        loadDashboard({ silent: true });
      } catch (error) {
        handleActionError(els.disableForm, els.disableFeedback, error);
      } finally {
        setBusy(button, false);
      }
    });
  }

  if (els.recoveryForm) {
    els.recoveryForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = els.recoveryForm.querySelector('[data-submit]');
      if (button.disabled) return;
      if (
        !validateSensitiveAction(
          els.recoveryForm,
          els.recoveryPassword,
          els.recoveryCode,
          els.recoveryFeedback
        )
      ) {
        return;
      }

      setBusy(button, true, 'Generating\u2026');
      try {
        const data = await api('/2fa/recovery-codes', {
          method: 'POST',
          body: {
            password: els.recoveryPassword.value,
            code: els.recoveryCode.value.trim()
          }
        });

        resetForm(els.recoveryForm);
        hideFeedback(els.recoveryFeedback);
        showRecoveryCodes(data.recoveryCodes);
        toast(
          data.message || 'New recovery codes generated. Previous codes no longer work.',
          'success'
        );
        loadDashboard({ silent: true });
      } catch (error) {
        handleActionError(els.recoveryForm, els.recoveryFeedback, error);
      } finally {
        setBusy(button, false);
      }
    });
  }

  if (els.recoveryCopy) {
    els.recoveryCopy.addEventListener('click', async () => {
      if (state.recoveryCodes.length === 0) return;
      const copied = await copyText(state.recoveryCodes.join('\n'));
      toast(
        copied
          ? 'Recovery codes copied. Store them somewhere safe.'
          : 'Copy failed. Select the codes and copy them manually.',
        copied ? 'success' : 'error'
      );
    });
  }

  if (els.recoveryDownload) {
    els.recoveryDownload.addEventListener('click', () => {
      if (state.recoveryCodes.length === 0) return;
      const lines = [
        'Secure Login \u2014 two-factor recovery codes',
        `Account: ${state.user ? state.user.username : 'unknown'}`,
        `Generated: ${new Date().toISOString()}`,
        '',
        ...state.recoveryCodes,
        '',
        'Each code can be used once. Store this file offline in a safe place.',
        'Regenerating codes invalidates every code listed above.'
      ];
      const blob = new Blob([lines.join('\n')], {
        type: 'text/plain;charset=utf-8'
      });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'secure-login-recovery-codes.txt';
      document.body.append(link);
      link.click();
      link.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast('Recovery codes downloaded. Keep the file offline.', 'info');
    });
  }

  if (els.recoveryClose) {
    els.recoveryClose.addEventListener('click', () => {
      hideRecoveryPanel();
      toast('Recovery codes hidden. They will not be shown again.', 'info');
    });
  }

  loadDashboard();
})();
