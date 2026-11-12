'use strict';

/**
 * Pending two-factor verification page.
 *
 * The server keeps the half-authenticated state in the session; this page only
 * submits the TOTP or single-use recovery code.
 */
(function () {
  const {
    api,
    applyApiErrors,
    clearFieldErrors,
    hideFormAlert,
    setBusy,
    setCsrfToken,
    setFieldError,
    showFormAlert,
    toast
  } = window.SecureLogin;

  const form = document.getElementById('two-factor-form');
  if (!form) return;

  const submitButton = form.querySelector('[data-submit]');
  const codeInput = form.elements.namedItem('code');
  const hint = document.querySelector('[data-code-hint]');
  const toggle = document.querySelector('[data-recovery-toggle]');
  const cancel = document.querySelector('[data-cancel-2fa]');
  let recoveryMode = false;

  function formatCode() {
    const raw = codeInput.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (/^[0-9]*$/.test(raw)) {
      codeInput.value = raw.slice(0, 6);
      return;
    }
    const trimmed = raw.slice(0, 10);
    codeInput.value =
      trimmed.length > 5 ? `${trimmed.slice(0, 5)}-${trimmed.slice(5)}` : trimmed;
  }

  codeInput.addEventListener('input', formatCode);

  if (toggle) {
    toggle.addEventListener('click', () => {
      recoveryMode = !recoveryMode;
      codeInput.value = '';
      codeInput.classList.toggle('is-recovery', recoveryMode);
      codeInput.setAttribute(
        'inputmode',
        recoveryMode ? 'text' : 'numeric'
      );
      codeInput.setAttribute(
        'placeholder',
        recoveryMode ? 'ABCDE-23456' : '000000'
      );
      toggle.textContent = recoveryMode
        ? 'Use authenticator code instead'
        : 'Use a recovery code';
      if (hint) {
        hint.textContent = recoveryMode
          ? 'Recovery codes are single-use. Enter one of the codes you saved when you enabled two-factor.'
          : 'Open your authenticator app and enter the current six-digit code.';
      }
      codeInput.focus();
    });
  }

  function validate() {
    clearFieldErrors(form);
    hideFormAlert(form);

    const value = codeInput.value.trim();
    if (!value) {
      setFieldError(
        form,
        'code',
        recoveryMode
          ? 'Enter a recovery code.'
          : 'Enter the six-digit code from your authenticator app.'
      );
      codeInput.focus();
      return false;
    }
    if (!/^\d{6}$/.test(value) && !/^[A-Z0-9]{5}-?[A-Z0-9]{5}$/i.test(value)) {
      setFieldError(
        form,
        'code',
        'Enter the six-digit code or a recovery code in the format ABCDE-23456.'
      );
      codeInput.focus();
      return false;
    }
    return true;
  }

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submitButton.disabled) return;
    if (!validate()) return;

    setBusy(submitButton, true, 'Verifying…');

    try {
      const data = await api('/auth/login/2fa', {
        method: 'POST',
        body: { code: codeInput.value.trim() }
      });

      setCsrfToken(data.csrfToken);
      codeInput.value = '';
      toast('Second factor verified. Opening your security console…', 'success');
      window.location.assign('/dashboard');
    } catch (error) {
      if (error.code === 'TWO_FACTOR_SESSION_EXPIRED') {
        showFormAlert(form, error.message, 'warning');
        window.setTimeout(() => {
          window.location.assign('/login?expired=1');
        }, 1400);
        return;
      }
      applyApiErrors(form, error);
      setBusy(submitButton, false);
      if (error.status === 429) {
        showFormAlert(form, error.message, 'warning');
      }
    }
  });

  if (cancel) {
    cancel.addEventListener('click', async () => {
      if (cancel.disabled) return;
      setBusy(cancel, true, 'Signing out…');
      try {
        await api('/auth/logout', { method: 'POST' });
      } catch (error) {
        // Even if the request fails, leave the pending flow.
      }
      window.location.assign('/login');
    });
  }
})();
