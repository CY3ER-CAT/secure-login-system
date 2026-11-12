'use strict';

/**
 * Sign-in page controller.
 *
 * Successful password verification either opens the dashboard immediately or,
 * when two-factor is enabled, moves to the pending-verification step.
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

  const form = document.getElementById('login-form');
  if (!form) return;

  const submitButton = form.querySelector('[data-submit]');
  const identifierInput = form.elements.namedItem('identifier');
  const passwordInput = form.elements.namedItem('password');
  const notice = document.querySelector('[data-login-notice]');

  const params = new URLSearchParams(window.location.search);
  if (notice) {
    if (params.get('expired') === '1') {
      notice.className = 'alert alert-warning';
      notice.textContent =
        'Your session expired or the verification window closed. Sign in again to continue.';
      notice.hidden = false;
    } else if (params.get('signedout') === '1') {
      notice.className = 'alert alert-success';
      notice.textContent = 'You have been signed out securely.';
      notice.hidden = false;
    } else if (params.get('registered') === '1') {
      notice.className = 'alert alert-success';
      notice.textContent = 'Account created. Sign in to continue.';
      notice.hidden = false;
    }
  }

  function validate() {
    clearFieldErrors(form);
    hideFormAlert(form);

    let firstInvalid = null;
    function fail(field, message) {
      const control = setFieldError(form, field, message);
      if (!firstInvalid) firstInvalid = control;
    }

    if (!identifierInput.value.trim()) {
      fail('identifier', 'Enter your username or email address.');
    }
    if (!passwordInput.value) {
      fail('password', 'Enter your password.');
    }

    if (firstInvalid) {
      firstInvalid.focus();
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
      const data = await api('/auth/login', {
        method: 'POST',
        body: {
          identifier: identifierInput.value.trim(),
          password: passwordInput.value
        }
      });

      setCsrfToken(data.csrfToken);
      passwordInput.value = '';

      if (data.twoFactorRequired) {
        toast('Password verified. Enter your second factor.', 'info');
        window.location.assign('/two-factor');
        return;
      }

      toast('Signed in. Opening your security console…', 'success');
      window.location.assign('/dashboard');
    } catch (error) {
      applyApiErrors(form, error);
      setBusy(submitButton, false);
      if (error.status === 429) {
        showFormAlert(form, error.message, 'warning');
      }
    }
  });
})();
