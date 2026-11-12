'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const { createTestApp, uniqueUser, getCsrf } = require('./support/test-app');

test('sets strict browser security headers without leaking the framework', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const response = await request(app).get('/');
  assert.equal(response.status, 200);

  const csp = response.headers['content-security-policy'];
  assert.ok(csp, 'Content-Security-Policy must be present');
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /style-src 'self'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /img-src 'self' data:/);
  assert.match(csp, /connect-src 'self'/);
  assert.doesNotMatch(csp, /unsafe-inline/);
  assert.doesNotMatch(csp, /unsafe-eval/);

  assert.equal(response.headers['x-frame-options'], 'DENY');
  assert.equal(response.headers['x-content-type-options'], 'nosniff');
  assert.equal(response.headers['referrer-policy'], 'no-referrer');
  assert.equal(response.headers['cross-origin-opener-policy'], 'same-origin');
  assert.equal(response.headers['cross-origin-resource-policy'], 'same-origin');
  assert.match(response.headers['permissions-policy'], /camera=\(\)/);
  assert.match(response.headers['permissions-policy'], /geolocation=\(\)/);
  assert.equal(response.headers['x-permitted-cross-domain-policies'], 'none');
  assert.equal(response.headers['x-powered-by'], undefined);
  assert.equal(response.headers['strict-transport-security'], undefined);
});

test('marks API responses as non-cacheable', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const health = await request(app).get('/api/health');
  assert.equal(health.status, 200);
  assert.deepEqual(health.body, { status: 'ok', environment: 'test' });
  assert.equal(health.headers['cache-control'], 'no-store, no-cache, must-revalidate, private');
  assert.equal(health.headers.pragma, 'no-cache');
  assert.equal(health.headers.expires, '0');
});

test('enables secure, HttpOnly cookies and HSTS in production mode', async (t) => {
  const app = createTestApp({
    nodeEnv: 'production',
    trustProxy: 1,
    sessionSecret: 'production-test-session-secret-0123456789abcdef',
    twoFactorEncryptionKey: 'b'.repeat(64),
    recoveryCodePepper: 'production-test-recovery-pepper-0123456789'
  });
  t.after(() => app.locals.close());

  // Production cookies are Secure, so express-session only issues them when the
  // request is seen as HTTPS. Simulate a TLS-terminating reverse proxy.
  const response = await request(app)
    .get('/api/csrf-token')
    .set('X-Forwarded-Proto', 'https');
  assert.equal(response.status, 200);
  assert.match(response.body.csrfToken, /^[a-f0-9]{256}$/);

  const cookieHeader = (response.headers['set-cookie'] || []).join(';');
  assert.match(cookieHeader, /sls\.sid=/);
  assert.match(cookieHeader, /;\s*Secure/i);
  assert.match(cookieHeader, /HttpOnly/i);
  assert.match(cookieHeader, /SameSite=Lax/i);

  assert.match(
    response.headers['strict-transport-security'],
    /max-age=15552000; includeSubDomains/
  );
  assert.match(
    response.headers['content-security-policy'],
    /upgrade-insecure-requests/
  );
});

test('returns safe errors for malformed and oversized JSON bodies', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const malformed = await request(app)
    .post('/api/auth/login')
    .set('Content-Type', 'application/json')
    .send('{"identifier":');
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body.code, 'INVALID_REQUEST');
  assert.equal(malformed.body.message, 'The request body is not valid JSON.');
  assert.ok(!JSON.stringify(malformed.body).includes('SyntaxError'));

  const oversized = await request(app)
    .post('/api/auth/login')
    .set('Content-Type', 'application/json')
    .send(JSON.stringify({ identifier: 'a'.repeat(40000), password: 'x' }));
  assert.equal(oversized.status, 413);
  assert.equal(oversized.body.code, 'PAYLOAD_TOO_LARGE');
  assert.equal(oversized.body.message, 'The request body is too large.');
});

test('rejects malformed CSRF tokens with a recoverable 403 payload', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const token = await getCsrf(agent);

  const response = await agent
    .post('/api/auth/logout')
    .set('X-CSRF-Token', '0'.repeat(256))
    .send();

  assert.equal(response.status, 403);
  assert.equal(response.body.code, 'CSRF_INVALID');
  assert.equal(
    response.body.message,
    'Your security token expired. Refresh the page and try again.'
  );
  assert.match(response.body.csrfToken, /^[a-f0-9]{256}$/);
});

test('does not expose stack traces or internal details on validation errors', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const token = await getCsrf(agent);
  const user = uniqueUser({ email: 'broken-email' });

  const response = await agent
    .post('/api/auth/register')
    .set('X-CSRF-Token', token)
    .send(user);

  assert.equal(response.status, 422);
  assert.equal(response.body.code, 'VALIDATION_ERROR');
  const serialized = JSON.stringify(response.body);
  assert.ok(!serialized.includes('at '));
  assert.ok(!serialized.includes('/Users/'));
  assert.ok(!serialized.includes('node_modules'));
  assert.ok(!serialized.includes(user.password));
});
