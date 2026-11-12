'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const request = require('supertest');

const {
  createTestApp,
  uniqueUser,
  register,
  login,
  logout,
  getCsrf,
  currentTotp,
  wrongTotp,
  enableTwoFactor
} = require('./support/test-app');

const ENCRYPTION_KEY = 'a'.repeat(64);
const RECOVERY_PEPPER = 'test-recovery-code-pepper-0123456789';

/** Decrypt a `v1:` AES-256-GCM value exactly as the application does. */
function decryptStoredSecret(encoded) {
  assert.match(encoded, /^v1:/);
  const payload = Buffer.from(encoded.slice(3), 'base64');
  const iv = payload.subarray(0, 12);
  const tag = payload.subarray(12, 28);
  const ciphertext = payload.subarray(28);
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    Buffer.from(ENCRYPTION_KEY, 'hex'),
    iv
  );
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

/** Recompute the expected HMAC for a recovery code, as the app stores it. */
function recoveryHash(code) {
  return crypto
    .createHmac('sha256', RECOVERY_PEPPER)
    .update(code.replace(/[^A-Za-z0-9]/g, '').toUpperCase())
    .digest('hex');
}

function twoFactorApp(overrides = {}) {
  return createTestApp({
    twoFactorRateLimitMax: 50,
    loginRateLimitMax: 100,
    registerRateLimitMax: 50,
    apiRateLimitMax: 2000,
    ...overrides
  });
}

test('sets up 2FA with a QR code and stores only an encrypted secret', async (t) => {
  const app = twoFactorApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);

  const anonymousToken = await getCsrf(agent);
  const anonymousSetup = await agent
    .post('/api/2fa/setup')
    .set('X-CSRF-Token', anonymousToken)
    .send();
  assert.equal(anonymousSetup.status, 401);
  assert.equal(anonymousSetup.body.code, 'UNAUTHENTICATED');

  const user = uniqueUser();
  const registration = await register(agent, user);
  assert.equal(registration.response.status, 201);

  const setup = await agent
    .post('/api/2fa/setup')
    .set('X-CSRF-Token', registration.csrfToken)
    .send();

  assert.equal(setup.status, 200);
  assert.equal(setup.body.message, 'Scan the QR code with your authenticator app.');
  assert.match(setup.body.secret, /^[A-Z2-7]{16,64}$/);
  assert.match(setup.body.otpauthUrl, /^otpauth:\/\/totp\//);
  assert.ok(setup.body.otpauthUrl.includes(`secret=${setup.body.secret}`));
  assert.match(setup.body.qrCodeDataUrl, /^data:image\/png;base64,/);

  const beforeEnable = app.locals.db
    .prepare('SELECT two_factor_enabled, two_factor_secret FROM users WHERE id = ?')
    .get(registration.response.body.user.id);
  assert.equal(beforeEnable.two_factor_enabled, 0);
  assert.equal(beforeEnable.two_factor_secret, null);

  const wrong = await agent
    .post('/api/2fa/enable')
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ code: wrongTotp(setup.body.secret) });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.body.code, 'INVALID_CODE');
  assert.equal(
    wrong.body.message,
    'That code is not valid. Check your authenticator app and try again.'
  );

  const stillDisabled = app.locals.db
    .prepare('SELECT two_factor_enabled, two_factor_secret FROM users WHERE id = ?')
    .get(registration.response.body.user.id);
  assert.equal(stillDisabled.two_factor_enabled, 0);
  assert.equal(stillDisabled.two_factor_secret, null);

  const enable = await agent
    .post('/api/2fa/enable')
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ code: currentTotp(setup.body.secret) });

  assert.equal(enable.status, 200);
  assert.equal(enable.body.message, 'Two-factor authentication enabled.');
  assert.equal(enable.body.twoFactorEnabled, true);
  assert.equal(enable.body.recoveryCodes.length, 10);
  for (const code of enable.body.recoveryCodes) {
    assert.match(code, /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
  }
  assert.ok(!JSON.stringify(enable.body).includes(setup.body.secret));

  const stored = app.locals.db
    .prepare('SELECT two_factor_enabled, two_factor_secret FROM users WHERE id = ?')
    .get(registration.response.body.user.id);
  assert.equal(stored.two_factor_enabled, 1);
  assert.match(stored.two_factor_secret, /^v1:/);
  assert.notEqual(stored.two_factor_secret, setup.body.secret);
  assert.equal(decryptStoredSecret(stored.two_factor_secret), setup.body.secret);

  const recoveryRows = app.locals.db
    .prepare('SELECT code_hash, used_at FROM recovery_codes WHERE user_id = ?')
    .all(registration.response.body.user.id);
  assert.equal(recoveryRows.length, 10);
  const expectedHashes = new Set(enable.body.recoveryCodes.map(recoveryHash));
  for (const row of recoveryRows) {
    assert.match(row.code_hash, /^[a-f0-9]{64}$/);
    assert.equal(row.used_at, null);
    assert.ok(expectedHashes.has(row.code_hash), 'codes must be stored as peppered HMACs');
  }

  const again = await agent
    .post('/api/2fa/setup')
    .set('X-CSRF-Token', registration.csrfToken)
    .send();
  assert.equal(again.status, 409);
  assert.equal(again.body.code, 'TWO_FACTOR_ALREADY_ENABLED');
});

test('requires the second factor at login and accepts a TOTP code', async (t) => {
  const app = twoFactorApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  const enrolled = await enableTwoFactor(agent, registration.csrfToken);
  assert.equal(enrolled.enable.status, 200);

  await logout(agent, registration.csrfToken);

  const pending = await login(agent, user.username, user.password);
  assert.equal(pending.response.status, 200);
  assert.deepEqual(Object.keys(pending.response.body).sort(), [
    'csrfToken',
    'message',
    'twoFactorRequired'
  ]);
  assert.equal(
    pending.response.body.message,
    'Password verified. Enter your authenticator code.'
  );
  assert.equal(pending.response.body.twoFactorRequired, true);
  assert.match(pending.response.body.csrfToken, /^[a-f0-9]{256}$/);

  const blockedDashboard = await agent.get('/api/dashboard');
  assert.equal(blockedDashboard.status, 401);
  assert.equal(blockedDashboard.body.code, 'UNAUTHENTICATED');

  const twoFactorPage = await agent.get('/two-factor');
  assert.equal(twoFactorPage.status, 200);
  assert.match(twoFactorPage.text, /two-factor-form/);

  const wrong = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', pending.csrfToken)
    .send({ code: wrongTotp(enrolled.secret) });
  assert.equal(wrong.status, 401);
  assert.equal(wrong.body.code, 'INVALID_CODE');
  assert.equal(
    wrong.body.message,
    'That verification code is not valid. Please try again.'
  );

  const verified = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', pending.csrfToken)
    .send({ code: currentTotp(enrolled.secret) });
  assert.equal(verified.status, 200);
  assert.equal(verified.body.message, 'Signed in successfully.');
  assert.equal(verified.body.user.username, user.username.toLowerCase());
  assert.equal(verified.body.user.twoFactorEnabled, true);
  assert.match(verified.body.csrfToken, /^[a-f0-9]{256}$/);

  const dashboard = await agent.get('/api/dashboard');
  assert.equal(dashboard.status, 200);
  assert.equal(dashboard.body.user.twoFactorEnabled, true);

  const events = app.locals.db
    .prepare('SELECT event_type FROM security_events WHERE user_id = ?')
    .all(registration.response.body.user.id)
    .map((event) => event.event_type);
  assert.ok(events.includes('login_success'));
  assert.ok(events.includes('two_factor_enabled'));
});

test('accepts each recovery code exactly once and normalizes formatting', async (t) => {
  const app = twoFactorApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  const enrolled = await enableTwoFactor(agent, registration.csrfToken);
  assert.equal(enrolled.enable.status, 200);
  const userId = registration.response.body.user.id;

  await logout(agent, registration.csrfToken);

  const firstPending = await login(agent, user.username, user.password);
  assert.equal(firstPending.response.body.twoFactorRequired, true);

  const firstCode = enrolled.recoveryCodes[0];
  const firstUse = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', firstPending.csrfToken)
    .send({ code: firstCode.toLowerCase() });
  assert.equal(firstUse.status, 200);
  assert.equal(firstUse.body.message, 'Signed in successfully.');

  let used = app.locals.db
    .prepare('SELECT COUNT(*) AS count FROM recovery_codes WHERE user_id = ? AND used_at IS NOT NULL')
    .get(userId);
  assert.equal(used.count, 1);

  const events = app.locals.db
    .prepare('SELECT event_type FROM security_events WHERE user_id = ?')
    .all(userId)
    .map((event) => event.event_type);
  assert.ok(events.includes('recovery_code_used'));

  await logout(agent, firstUse.body.csrfToken);

  const secondPending = await login(agent, user.username, user.password);
  assert.equal(secondPending.response.body.twoFactorRequired, true);

  const replay = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', secondPending.csrfToken)
    .send({ code: firstCode });
  assert.equal(replay.status, 401);
  assert.equal(replay.body.code, 'INVALID_CODE');

  const secondUse = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', secondPending.csrfToken)
    .send({ code: enrolled.recoveryCodes[1] });
  assert.equal(secondUse.status, 200);

  used = app.locals.db
    .prepare('SELECT COUNT(*) AS count FROM recovery_codes WHERE user_id = ? AND used_at IS NOT NULL')
    .get(userId);
  assert.equal(used.count, 2);

  const storedHashes = app.locals.db
    .prepare('SELECT code_hash FROM recovery_codes WHERE user_id = ?')
    .all(userId)
    .map((row) => row.code_hash);
  assert.ok(!storedHashes.includes(firstCode));
  assert.ok(!storedHashes.includes(firstCode.replace('-', '')));
});

test('disables 2FA with a password and code, then clears the stored secret', async (t) => {
  const app = twoFactorApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  const enrolled = await enableTwoFactor(agent, registration.csrfToken);
  assert.equal(enrolled.enable.status, 200);
  const userId = registration.response.body.user.id;

  const wrongPassword = await agent
    .post('/api/2fa/disable')
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ password: 'Wr0ng!Password#2026', code: currentTotp(enrolled.secret) });
  assert.equal(wrongPassword.status, 401);
  assert.equal(wrongPassword.body.code, 'INVALID_PASSWORD');
  assert.equal(wrongPassword.body.message, 'Your password is incorrect.');

  const wrongCode = await agent
    .post('/api/2fa/disable')
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ password: user.password, code: wrongTotp(enrolled.secret) });
  assert.equal(wrongCode.status, 401);
  assert.equal(wrongCode.body.code, 'INVALID_CODE');
  assert.equal(wrongCode.body.message, 'That verification code is not valid.');

  const stillEnabled = app.locals.db
    .prepare('SELECT two_factor_enabled FROM users WHERE id = ?')
    .get(userId);
  assert.equal(stillEnabled.two_factor_enabled, 1);

  const disable = await agent
    .post('/api/2fa/disable')
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ password: user.password, code: currentTotp(enrolled.secret) });
  assert.equal(disable.status, 200);
  assert.equal(disable.body.message, 'Two-factor authentication disabled.');
  assert.equal(disable.body.twoFactorEnabled, false);

  const cleared = app.locals.db
    .prepare('SELECT two_factor_enabled, two_factor_secret FROM users WHERE id = ?')
    .get(userId);
  assert.equal(cleared.two_factor_enabled, 0);
  assert.equal(cleared.two_factor_secret, null);
  assert.equal(
    app.locals.db.prepare('SELECT COUNT(*) AS count FROM recovery_codes WHERE user_id = ?').get(userId)
      .count,
    0
  );

  const again = await agent
    .post('/api/2fa/disable')
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ password: user.password, code: currentTotp(enrolled.secret) });
  assert.equal(again.status, 409);
  assert.equal(again.body.code, 'TWO_FACTOR_NOT_ENABLED');

  await logout(agent, registration.csrfToken);

  const passwordOnly = await login(agent, user.username, user.password);
  assert.equal(passwordOnly.response.status, 200);
  assert.equal(passwordOnly.response.body.twoFactorRequired, undefined);
  assert.equal(passwordOnly.response.body.user.twoFactorEnabled, false);
});

test('regenerates recovery codes and invalidates every previous code', async (t) => {
  const app = twoFactorApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  const enrolled = await enableTwoFactor(agent, registration.csrfToken);
  assert.equal(enrolled.enable.status, 200);
  const userId = registration.response.body.user.id;
  const oldCodes = enrolled.recoveryCodes;

  const wrongPassword = await agent
    .post('/api/2fa/recovery-codes')
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ password: 'Wr0ng!Password#2026', code: currentTotp(enrolled.secret) });
  assert.equal(wrongPassword.status, 401);
  assert.equal(wrongPassword.body.code, 'INVALID_PASSWORD');

  const regenerated = await agent
    .post('/api/2fa/recovery-codes')
    .set('X-CSRF-Token', registration.csrfToken)
    .send({ password: user.password, code: currentTotp(enrolled.secret) });
  assert.equal(regenerated.status, 200);
  assert.equal(
    regenerated.body.message,
    'New recovery codes generated. Previous codes no longer work.'
  );
  assert.equal(regenerated.body.recoveryCodes.length, 10);

  const newCodes = regenerated.body.recoveryCodes;
  assert.equal(new Set([...oldCodes, ...newCodes]).size, 20);
  for (const code of newCodes) {
    assert.match(code, /^[A-Z2-9]{5}-[A-Z2-9]{5}$/);
  }

  const rows = app.locals.db
    .prepare('SELECT code_hash FROM recovery_codes WHERE user_id = ?')
    .all(userId);
  assert.equal(rows.length, 10);
  const stored = new Set(rows.map((row) => row.code_hash));
  for (const oldCode of oldCodes) {
    assert.ok(!stored.has(recoveryHash(oldCode)));
  }
  for (const newCode of newCodes) {
    assert.ok(stored.has(recoveryHash(newCode)));
  }

  const events = app.locals.db
    .prepare('SELECT event_type FROM security_events WHERE user_id = ?')
    .all(userId)
    .map((event) => event.event_type);
  assert.ok(events.includes('recovery_codes_regenerated'));

  await logout(agent, registration.csrfToken);

  const pending = await login(agent, user.username, user.password);
  assert.equal(pending.response.body.twoFactorRequired, true);

  const oldCodeRejected = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', pending.csrfToken)
    .send({ code: oldCodes[0] });
  assert.equal(oldCodeRejected.status, 401);
  assert.equal(oldCodeRejected.body.code, 'INVALID_CODE');

  const newCodeAccepted = await agent
    .post('/api/auth/login/2fa')
    .set('X-CSRF-Token', pending.csrfToken)
    .send({ code: newCodes[0] });
  assert.equal(newCodeAccepted.status, 200);
  assert.equal(newCodeAccepted.body.message, 'Signed in successfully.');
});
