'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const {
  createTestApp,
  uniqueUser,
  getCsrf,
  register,
  login,
  logout,
  enableTwoFactor,
  wrongTotp
} = require('./support/test-app');

test('rate limits repeated failed logins for the same IP and identifier', async (t) => {
  const app = createTestApp({
    loginRateLimitMax: 2,
    accountLockThreshold: 100,
    registerRateLimitMax: 50,
    apiRateLimitMax: 1000
  });
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  await logout(agent, registration.csrfToken);

  const csrfToken = await getCsrf(agent);

  const first = await login(agent, user.username, 'Wr0ng!Password#2026', csrfToken);
  assert.equal(first.response.status, 401);

  const second = await login(agent, user.username, 'Wr0ng!Password#2026', csrfToken);
  assert.equal(second.response.status, 401);

  const third = await login(agent, user.username, 'Wr0ng!Password#2026', csrfToken);
  assert.equal(third.response.status, 429);
  assert.equal(third.response.body.code, 'RATE_LIMITED');
  assert.equal(
    third.response.body.message,
    'Too many sign-in attempts. Please wait a few minutes before trying again.'
  );

  const correctButLimited = await login(agent, user.username, user.password, csrfToken);
  assert.equal(correctButLimited.response.status, 429);
  assert.equal(correctButLimited.response.body.code, 'RATE_LIMITED');
});

test('locks an account after the configured number of failed passwords', async (t) => {
  const app = createTestApp({
    accountLockThreshold: 3,
    loginRateLimitMax: 100,
    registerRateLimitMax: 50,
    apiRateLimitMax: 1000
  });
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  await logout(agent, registration.csrfToken);

  const csrfToken = await getCsrf(agent);

  const first = await login(agent, user.username, 'Wr0ng!Password#2026', csrfToken);
  assert.equal(first.response.status, 401);

  const second = await login(agent, user.username, 'Wr0ng!Password#2026', csrfToken);
  assert.equal(second.response.status, 401);

  const third = await login(agent, user.username, 'Wr0ng!Password#2026', csrfToken);
  assert.equal(third.response.status, 429);
  assert.equal(third.response.body.code, 'ACCOUNT_LOCKED');

  const correctWhileLocked = await login(agent, user.username, user.password, csrfToken);
  assert.equal(correctWhileLocked.response.status, 429);
  assert.equal(correctWhileLocked.response.body.code, 'ACCOUNT_LOCKED');

  const row = app.locals.db
    .prepare('SELECT failed_login_attempts, locked_until FROM users WHERE username = ?')
    .get(user.username.toLowerCase());
  assert.equal(row.failed_login_attempts, 3);
  assert.ok(Date.parse(row.locked_until) > Date.now());

  const events = app.locals.db
    .prepare('SELECT event_type FROM security_events WHERE user_id = ?')
    .all(registration.response.body.user.id)
    .map((event) => event.event_type);
  assert.ok(events.includes('account_locked'));

  // The lock is scoped to the targeted account, not the whole IP.
  const otherAgent = request.agent(app);
  const other = uniqueUser();
  const otherRegistration = await register(otherAgent, other);
  assert.equal(otherRegistration.response.status, 201);
  const otherLogin = await login(otherAgent, other.username, other.password, otherRegistration.csrfToken);
  assert.equal(otherLogin.response.status, 200);
});

test('rate limits account creation from a single network', async (t) => {
  const app = createTestApp({
    registerRateLimitMax: 2,
    loginRateLimitMax: 100,
    apiRateLimitMax: 1000
  });
  t.after(() => app.locals.close());

  const first = await register(request.agent(app), uniqueUser());
  assert.equal(first.response.status, 201);

  const second = await register(request.agent(app), uniqueUser());
  assert.equal(second.response.status, 201);

  const third = await register(request.agent(app), uniqueUser());
  assert.equal(third.response.status, 429);
  assert.equal(third.response.body.code, 'RATE_LIMITED');
  assert.equal(
    third.response.body.message,
    'Too many accounts created from this network. Please try again later.'
  );

  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 2);
});

test('rate limits repeated failed two-factor codes', async (t) => {
  const app = createTestApp({
    twoFactorRateLimitMax: 2,
    loginRateLimitMax: 100,
    registerRateLimitMax: 50,
    apiRateLimitMax: 1000
  });
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  const enrolled = await enableTwoFactor(agent, registration.csrfToken);
  assert.equal(enrolled.enable.status, 200);

  await logout(agent, registration.csrfToken);

  const pending = await login(agent, user.username, user.password);
  assert.equal(pending.response.status, 200);
  assert.equal(pending.response.body.twoFactorRequired, true);

  const first = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', pending.csrfToken)
    .send({ code: wrongTotp(enrolled.secret) });
  assert.equal(first.status, 401);
  assert.equal(first.body.code, 'INVALID_CODE');

  const second = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', pending.csrfToken)
    .send({ code: wrongTotp(enrolled.secret) });
  assert.equal(second.status, 401);

  const third = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', pending.csrfToken)
    .send({ code: wrongTotp(enrolled.secret) });
  assert.equal(third.status, 429);
  assert.equal(third.body.code, 'RATE_LIMITED');
  assert.equal(
    third.body.message,
    'Too many verification attempts. Please wait a few minutes and try again.'
  );
});
