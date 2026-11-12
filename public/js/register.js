'use strict';

/**
 * Registration page controller.
 *
 * Client-side checks are a convenience only; the server re-validates every
 * field with express-validator and the authoritative password policy.
 */
(function () {
  const {
    api,
    applyApiErrors,
    clearFieldErrors,
    evaluatePassword,
    hideFormAlert,
    initPasswordStrength,
    setBusy,
    setCsrfToken,
    setFieldError,
    showFormAlert,
    toast
  } = window.SecureLogin;

  const form = document.getElementById('register-form');
  if (!form) return;

  const submitButton = form.querySelector('[data-submit]');
  const fullNameInput = form.elements.namedItem('full_name');
  const emailInput = form.elements.namedItem('email');
  const usernameInput = form.elements.namedItem('username');
  const passwordInput = form.elements.namedItem('password');
  const confirmInput = form.elements.namedItem('confirm_password');

  initPasswordStrength({
    input: passwordInput,
    username: usernameInput,
    email: emailInput
  });

  function validate() {
    clearFieldErrors(form);
    hideFormAlert(form);

    let firstInvalid = null;

    function fail(field, message) {
      const control = setFieldError(form, field, message);
      if (!firstInvalid) firstInvalid = control;
    }

    if (!fullNameInput.value.trim()) {
      fail('full_name', 'Enter your full name.');
    } else if (fullNameInput.value.trim().length < 2) {
      fail('full_name', 'Full name must be at least 2 characters.');
    }

    if (!emailInput.value.trim()) {
      fail('email', 'Enter your email address.');
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value.trim())) {
      fail('email', 'Enter a valid email address.');
    }

    if (!usernameInput.value.trim()) {
      fail('username', 'Choose a username.');
    } else if (!/^[a-z0-9_]{3,30}$/i.test(usernameInput.value.trim())) {
      fail(
        'username',
        'Use 3–30 characters: letters, numbers and underscores only.'
      );
    }

    if (!passwordInput.value) {
      fail('password', 'Choose a password.');
    } else {
      const strength = evaluatePassword(passwordInput.value, {
        username: usernameInput.value,
        email: emailInput.value
      });
      if (!strength.valid) {
        const messages = {
          length: 'Use 12–72 characters (within the bcrypt byte limit).',
          upper: 'Add at least one uppercase letter.',
          lower: 'Add at least one lowercase letter.',
          number: 'Add at least one number.',
          symbol: 'Add at least one symbol.',
          noSpace: 'Remove spaces from the password.',
          noPersonal: 'Do not include your username or email address.',
          notCommon: 'This password is too common. Choose something unique.',
          noSequence: 'Avoid repeated characters and predictable sequences.'
        };
        const failed = Object.keys(strength.checks).find(
          (key) => !strength.checks[key]
        );
        fail('password', messages[failed] || 'Choose a stronger password.');
      }
    }

    if (!confirmInput.value) {
      fail('confirm_password', 'Re-enter your password.');
    } else if (confirmInput.value !== passwordInput.value) {
      fail('confirm_password', 'Passwords do not match.');
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

    setBusy(submitButton, true, 'Creating account…');

    try {
      const data = await api('/auth/register', {
        method: 'POST',
        body: {
          full_name: fullNameInput.value.trim(),
          email: emailInput.value.trim(),
          username: usernameInput.value.trim(),
          password: passwordInput.value,
          confirm_password: confirmInput.value
        }
      });

      setCsrfToken(data.csrfToken);
      passwordInput.value = '';
      confirmInput.value = '';
      toast('Account created. Opening your security console…', 'success');
      window.setTimeout(() => {
        window.location.assign('/dashboard');
      }, 550);
    } catch (error) {
      applyApiErrors(form, error);
      setBusy(submitButton, false);
      if (error.status === 429) {
        showFormAlert(form, error.message, 'warning');
      }
    }
  });

  confirmInput.addEventListener('input', () => {
    if (!confirmInput.value) return;
    if (confirmInput.value === passwordInput.value) {
      const field = confirmInput.closest('.field');
      if (field) {
        field.classList.remove('has-error');
        const error = field.querySelector('.field-error');
        if (error) error.remove();
      }
      confirmInput.removeAttribute('aria-invalid');
    }
  });
})();
