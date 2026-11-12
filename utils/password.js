'use strict';

const bcrypt = require('bcrypt');

const MIN_LENGTH = 12;
const MAX_BYTES = 72;
const MAX_LENGTH = 72;

// Small, deliberately conservative blocklist. A production system would use
// a breached-password service (e.g. HIBP k-anonymity) in addition to this.
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

const SYMBOL_PATTERN = /[^A-Za-z0-9\s]/;
const UPPER_PATTERN = /[A-Z]/;
const LOWER_PATTERN = /[a-z]/;
const NUMBER_PATTERN = /[0-9]/;

/**
 * Server-side password policy. The browser mirrors these rules for UX,
 * but this function is the authoritative check.
 */
function validatePasswordStrength(password, { username = '', email = '' } = {}) {
  const errors = [];

  if (typeof password !== 'string' || password.length === 0) {
    return { valid: false, errors: ['Password is required.'] };
  }

  if (password.length < MIN_LENGTH) {
    errors.push(`Password must be at least ${MIN_LENGTH} characters long.`);
  }
  if (password.length > MAX_LENGTH || Buffer.byteLength(password, 'utf8') > MAX_BYTES) {
    errors.push('Password must be 72 characters or fewer (bcrypt limit).');
  }
  if (!UPPER_PATTERN.test(password)) {
    errors.push('Password must include an uppercase letter.');
  }
  if (!LOWER_PATTERN.test(password)) {
    errors.push('Password must include a lowercase letter.');
  }
  if (!NUMBER_PATTERN.test(password)) {
    errors.push('Password must include a number.');
  }
  if (!SYMBOL_PATTERN.test(password)) {
    errors.push('Password must include a symbol.');
  }
  if (/\s/.test(password)) {
    errors.push('Password must not contain spaces.');
  }

  const normalized = password.toLowerCase();
  if (COMMON_PASSWORDS.has(normalized)) {
    errors.push('This password is too common. Choose something unique.');
  }

  const localPart = String(email).split('@')[0]?.toLowerCase() || '';
  if (username && username.length >= 3 && normalized.includes(username.toLowerCase())) {
    errors.push('Password must not contain your username.');
  }
  if (localPart.length >= 3 && normalized.includes(localPart)) {
    errors.push('Password must not contain your email address.');
  }

  // Reject long runs such as "aaaaaaaaaaaa" or "123456789012".
  if (/(.)\1{5,}/.test(password)) {
    errors.push('Password must not contain long repeated character sequences.');
  }
  if (/(0123456789|1234567890|abcdefghij|qwertyuiop)/i.test(password)) {
    errors.push('Password must not contain a predictable sequence.');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * A per-instance password service keeps the bcrypt cost factor aligned with
 * the configured work factor, including a dummy hash for timing equalisation.
 */
function createPasswordService(rounds) {
  if (!Number.isInteger(rounds) || rounds < 4 || rounds > 15) {
    throw new Error('bcrypt rounds must be an integer between 4 and 15.');
  }

  const dummyHash = bcrypt.hashSync(
    'timing-equalisation-placeholder-not-a-real-password',
    rounds
  );

  return {
    rounds,
    async hash(password) {
      return bcrypt.hash(password, rounds);
    },
    async verify(password, hash) {
      return bcrypt.compare(password, hash);
    },
    /**
     * Always run one bcrypt comparison, even when the account does not exist.
     * This reduces the timing difference between unknown users and bad passwords.
     */
    async verifyDummy(password) {
      await bcrypt.compare(String(password || ''), dummyHash);
      return false;
    },
    validateStrength: validatePasswordStrength
  };
}

module.exports = {
  createPasswordService,
  validatePasswordStrength,
  MIN_LENGTH,
  MAX_LENGTH
};
