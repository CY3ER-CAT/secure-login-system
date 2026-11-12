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
  logout
} = require('./support/test-app');

function sessionCookieFrom(response) {
  const cookies = response.headers['set-cookie'] || [];
  const sessionCookie = cookies.find((cookie) => cookie.startsWith('sls.sid='));
  assert.ok(sessionCookie, 'expected the response to set a session cookie');
  return sessionCookie.split(';')[0];
}

test('registers a new account, normalises input and stores only a bcrypt hash', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  user.full_name = '  Ada   Lovelace  ';
  user.email = user.email.toUpperCase();
  user.username = user.username.toUpperCase();

  const { response } = await register(agent, user);

  assert.equal(response.status, 201);
  assert.equal(response.body.message, 'Account created successfully.');
  assert.equal(response.body.user.fullName, 'Ada Lovelace');
  assert.equal(response.body.user.email, user.email.toLowerCase());
  assert.equal(response.body.user.username, user.username.toLowerCase());
  assert.equal(response.body.user.twoFactorEnabled, false);
  assert.equal(response.body.user.lastLoginAt, null);
  assert.match(response.body.csrfToken, /^[a-f0-9]{256}$/);
  assert.equal(response.body.user.password, undefined);
  assert.equal(response.body.user.passwordHash, undefined);
  assert.equal(response.body.user.password_hash, undefined);

  const row = app.locals.db
    .prepare('SELECT * FROM users WHERE email = ?')
    .get(user.email.toLowerCase());
  assert.ok(row, 'the user should exist in SQLite');
  assert.match(row.password_hash, /^\$2[aby]\$/);
  assert.notEqual(row.password_hash, user.password);
  assert.ok(!JSON.stringify(row).includes(user.password));

  const cookieHeader = (response.headers['set-cookie'] || []).join(';');
  assert.match(cookieHeader, /sls\.sid=/);
  assert.match(cookieHeader, /HttpOnly/i);
  assert.match(cookieHeader, /SameSite=Lax/i);
  assert.match(cookieHeader, /Path=\//i);
  assert.doesNotMatch(cookieHeader, /;\s*Secure/i);

  const dashboard = await agent.get('/api/dashboard');
  assert.equal(dashboard.status, 200);
});

test('rejects a duplicate email address with a field-level 409', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const first = uniqueUser();
  await register(request.agent(app), first);

  const second = uniqueUser({ email: first.email });
  const { response } = await register(request.agent(app), second);

  assert.equal(response.status, 409);
  assert.equal(response.body.code, 'EMAIL_IN_USE');
  assert.equal(response.body.errors.email, 'An account with this email address already exists.');
  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 1);
});

test('rejects a duplicate username case-insensitively with a field-level 409', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const first = uniqueUser();
  await register(request.agent(app), first);

  const second = uniqueUser({ username: first.username.toUpperCase() });
  const { response } = await register(request.agent(app), second);

  assert.equal(response.status, 409);
  assert.equal(response.body.code, 'USERNAME_IN_USE');
  assert.equal(response.body.errors.username, 'That username is already taken.');
  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 1);
});

test('rejects an invalid email address before creating an account', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const { response } = await register(
    request.agent(app),
    uniqueUser({ email: 'not-an-email' })
  );

  assert.equal(response.status, 422);
  assert.equal(response.body.code, 'VALIDATION_ERROR');
  assert.equal(response.body.errors.email, 'Enter a valid email address.');
  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 0);
});

test('rejects weak passwords and mismatched confirmation fields', async (t) => {
  const app = createTestApp({ registerRateLimitMax: 20 });
  t.after(() => app.locals.close());

  const weak = await register(
    request.agent(app),
    uniqueUser({ password: 'password', confirm_password: 'password' })
  );
  assert.equal(weak.response.status, 422);
  assert.equal(weak.response.body.code, 'VALIDATION_ERROR');
  assert.match(weak.response.body.errors.password, /at least 12 characters/i);

  const mismatch = await register(
    request.agent(app),
    uniqueUser({
      password: 'V3rified!Access#2026',
      confirm_password: 'Different!Access#2026'
    })
  );
  assert.equal(mismatch.response.status, 422);
  assert.equal(mismatch.response.body.errors.confirm_password, 'Passwords do not match.');

  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 0);
});

test('signs in with username and email, rotating the session each time', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  assert.equal(registration.response.status, 201);

  const firstCookie = sessionCookieFrom(registration.response);
  const signedOut = await logout(agent, registration.csrfToken);
  assert.equal(signedOut.status, 200);

  const byUsername = await login(agent, user.username, user.password);
  assert.equal(byUsername.response.status, 200);
  assert.equal(byUsername.response.body.message, 'Signed in successfully.');
  assert.equal(byUsername.response.body.user.username, user.username.toLowerCase());
  assert.notEqual(sessionCookieFrom(byUsername.response), firstCookie);

  const authenticated = await agent.get('/api/dashboard');
  assert.equal(authenticated.status, 200);

  const signedOutAgain = await logout(agent, byUsername.csrfToken);
  assert.equal(signedOutAgain.status, 200);

  const byEmail = await login(agent, user.email.toUpperCase(), user.password);
  assert.equal(byEmail.response.status, 200);
  assert.equal(byEmail.response.body.user.email, user.email.toLowerCase());
});

test('returns the same generic error for a wrong password and an unknown account', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  await logout(agent, registration.csrfToken);

  const wrongPassword = await login(agent, user.username, 'Wr0ng!Password#2026');
  assert.equal(wrongPassword.response.status, 401);
  assert.equal(wrongPassword.response.body.code, 'INVALID_CREDENTIALS');
  assert.equal(wrongPassword.response.body.message, 'Invalid username or password.');

  const unknown = await login(agent, 'nobody_here', 'Wr0ng!Password#2026');
  assert.equal(unknown.response.status, 401);
  assert.equal(unknown.response.body.code, 'INVALID_CREDENTIALS');
  assert.equal(unknown.response.body.message, wrongPassword.response.body.message);

  const row = app.locals.db
    .prepare('SELECT failed_login_attempts FROM users WHERE username = ?')
    .get(user.username.toLowerCase());
  assert.equal(row.failed_login_attempts, 1);
});

test('treats SQL injection payloads as literal data and leaves the table intact', async (t) => {
  const app = createTestApp({
    registerRateLimitMax: 50,
    apiRateLimitMax: 1000,
    accountLockThreshold: 100
  });
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  await logout(agent, registration.csrfToken);

  const payloads = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
    "operator'; DROP TABLE users; --"
  ];

  for (const payload of payloads) {
    const attempt = await login(agent, payload, 'anything');
    assert.equal(attempt.response.status, 401, `payload should not bypass auth: ${payload}`);
    assert.equal(attempt.response.body.code, 'INVALID_CREDENTIALS');
  }

  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 1);

  const legitimate = await login(agent, user.username, user.password);
  assert.equal(legitimate.response.status, 200);

  const maliciousRegistrations = [
    uniqueUser({ username: "admin'--" }),
    uniqueUser({ email: "sqli'; DROP TABLE users; --@example.com" }),
    uniqueUser({ full_name: "Robert'); DROP TABLE users;--" })
  ];

  for (const malicious of maliciousRegistrations) {
    const attempt = await register(request.agent(app), malicious);
    assert.equal(attempt.response.status, 422);
    assert.equal(attempt.response.body.code, 'VALIDATION_ERROR');
  }

  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM users').get().count, 1);
});

test('rejects state-changing requests without a valid CSRF token and issues a fresh one', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  await logout(agent, registration.csrfToken);

  const missing = await agent
    .post('/api/auth/login')
    .send({ identifier: user.username, password: user.password });

  assert.equal(missing.status, 403);
  assert.equal(missing.body.code, 'CSRF_INVALID');
  assert.match(missing.body.csrfToken, /^[a-f0-9]{256}$/);

  const invalid = await agent
    .post('/api/auth/login')
    .set('X-CSRF-Token', 'f'.repeat(256))
    .send({ identifier: user.username, password: user.password });

  assert.equal(invalid.status, 403);
  assert.equal(invalid.body.code, 'CSRF_INVALID');
  assert.equal(invalid.body.csrfToken, missing.body.csrfToken);

  const accepted = await login(agent, user.username, user.password, invalid.body.csrfToken);
  assert.equal(accepted.response.status, 200);
});

test('regenerates the session ID on registration and invalidates the old session', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const csrfToken = await getCsrf(agent);
  const csrfResponse = await agent.get('/api/csrf-token');
  const oldCookie = sessionCookieFrom(csrfResponse);

  const registration = await agent
    .post('/api/auth/register')
    .set('X-CSRF-Token', csrfToken)
    .send(user);

  assert.equal(registration.status, 201);
  const newCookie = sessionCookieFrom(registration);
  assert.notEqual(newCookie, oldCookie);

  const withOldSession = await request(app).get('/api/dashboard').set('Cookie', oldCookie);
  assert.equal(withOldSession.status, 401);

  const withNewSession = await agent.get('/api/dashboard');
  assert.equal(withNewSession.status, 200);
});

test('destroys the server-side session and clears the cookie on logout', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const registration = await register(agent, uniqueUser());
  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM sessions').get().count, 1);

  const response = await logout(agent, registration.csrfToken);

  assert.equal(response.status, 200);
  assert.equal(response.body.message, 'Signed out successfully.');
  const cookieHeader = (response.headers['set-cookie'] || []).join(';');
  assert.match(cookieHeader, /sls\.sid=;/);
  assert.match(cookieHeader, /Expires=Thu, 01 Jan 1970/i);
  assert.equal(app.locals.db.prepare('SELECT COUNT(*) AS count FROM sessions').get().count, 0);

  const api = await agent.get('/api/dashboard');
  assert.equal(api.status, 401);
  assert.equal(api.body.code, 'UNAUTHENTICATED');

  const page = await agent.get('/dashboard');
  assert.equal(page.status, 302);
  assert.equal(page.headers.location, '/login?next=%2Fdashboard');
});

test('expires server-side sessions after the configured TTL', async (t) => {
  const ttlMs = 60 * 60 * 1000;
  const app = createTestApp({ sessionTtlMs: ttlMs });
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const registration = await register(agent, uniqueUser());
  assert.equal(registration.response.status, 201);

  const sessionRow = app.locals.db
    .prepare('SELECT sid, expire FROM sessions ORDER BY expire DESC LIMIT 1')
    .get();
  const remaining = sessionRow.expire - Date.now();
  assert.ok(
    remaining > ttlMs - 60 * 1000 && remaining <= ttlMs,
    `stored expiry should reflect the configured TTL, got ${remaining}ms`
  );

  const before = await agent.get('/api/auth/me');
  assert.equal(before.status, 200);

  // Force the server-side record into the past: the store must reject it even
  // though the browser still presents a validly signed cookie.
  app.locals.db
    .prepare('UPDATE sessions SET expire = ? WHERE sid = ?')
    .run(Date.now() - 1, sessionRow.sid);

  const afterExpiry = await agent.get('/api/dashboard');
  assert.equal(afterExpiry.status, 401);
  assert.equal(afterExpiry.body.code, 'UNAUTHENTICATED');
});
