'use strict';

const request = require('supertest');
const { createApp } = require('../../app');

/**
 * Deterministic configuration for the automated suite:
 * - in-memory SQLite database (isolated per app instance)
 * - low bcrypt work factor to keep tests fast
 * - fixed encryption/pepper values so 2FA assertions are reproducible
 */
const BASE_OVERRIDES = {
  nodeEnv: 'test',
  databasePath: ':memory:',
  sessionSecret: 'test-session-secret-0123456789abcdef0123456789abcdef',
  twoFactorEncryptionKey: 'a'.repeat(64),
  recoveryCodePepper: 'test-recovery-code-pepper-0123456789',
  bcryptRounds: 4
};

let sequence = 0;

function uniqueUser(overrides = {}) {
  sequence += 1;
  const suffix = `${Date.now().toString(36)}${sequence}`.slice(-10);
  return {
    full_name: 'Test Operator',
    email: `operator.${suffix}@example.com`,
    username: `operator_${suffix}`,
    password: 'V3rified!Access#2026',
    confirm_password: 'V3rified!Access#2026',
    ...overrides
  };
}

function createTestApp(overrides = {}) {
  return createApp({ ...BASE_OVERRIDES, ...overrides });
}

function agentFor(app) {
  return request.agent(app);
}

async function getCsrf(agent) {
  const response = await agent.get('/api/csrf-token');
  if (response.status !== 200 || typeof response.body.csrfToken !== 'string') {
    throw new Error(`Unable to obtain a CSRF token (status ${response.status}).`);
  }
  return response.body.csrfToken;
}

async function register(agent, user = uniqueUser()) {
  const csrfToken = await getCsrf(agent);
  const response = await agent
    .post('/api/auth/register')
    .set('X-CSRF-Token', csrfToken)
    .send(user);

  return {
    response,
    user,
    csrfToken: response.body.csrfToken || csrfToken
  };
}

async function login(agent, identifier, password, csrfToken) {
  const token = csrfToken || (await getCsrf(agent));
  const response = await agent
    .post('/api/auth/login')
    .set('X-CSRF-Token', token)
    .send({ identifier, password });

  return {
    response,
    csrfToken: response.body.csrfToken || token
  };
}

async function logout(agent, csrfToken) {
  const token = csrfToken || (await getCsrf(agent));
  return agent.post('/api/auth/logout').set('X-CSRF-Token', token).send();
}

/** The current valid TOTP value for a base32 secret. */
function currentTotp(secret) {
  // otplib is configured globally by utils/totp.js (window: 1, step: 30).
  const { authenticator } = require('otplib');
  return authenticator.generate(secret);
}

/** A six-digit value that is not the current code (used for negative tests). */
function wrongTotp(secret) {
  const current = currentTotp(secret);
  return String((Number(current) + 1) % 1000000).padStart(6, '0');
}

/**
 * Run the full 2FA enrolment flow for an authenticated agent.
 * Returns the setup/enable responses plus the plaintext secret and codes.
 */
async function enableTwoFactor(agent, csrfToken) {
  const setup = await agent
    .post('/api/2fa/setup')
    .set('X-CSRF-Token', csrfToken)
    .send();

  if (setup.status !== 200) {
    throw new Error(`2FA setup failed with status ${setup.status}`);
  }

  const enable = await agent
    .post('/api/2fa/enable')
    .set('X-CSRF-Token', csrfToken)
    .send({ code: currentTotp(setup.body.secret) });

  return {
    setup,
    enable,
    secret: setup.body.secret,
    recoveryCodes: enable.body.recoveryCodes
  };
}

module.exports = {
  BASE_OVERRIDES,
  uniqueUser,
  createTestApp,
  agentFor,
  getCsrf,
  register,
  login,
  logout,
  currentTotp,
  wrongTotp,
  enableTwoFactor
};
