'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const {
  createTestApp,
  uniqueUser,
  register,
  login,
  logout
} = require('./support/test-app');

test('protects the dashboard page and API from anonymous requests', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const api = await request(app).get('/api/dashboard');
  assert.equal(api.status, 401);
  assert.equal(api.body.code, 'UNAUTHENTICATED');
  assert.equal(api.body.message, 'Authentication required. Please sign in.');
  assert.equal(api.headers['cache-control'], 'no-store, no-cache, must-revalidate, private');

  const page = await request(app).get('/dashboard');
  assert.equal(page.status, 302);
  assert.equal(page.headers.location, '/login?next=%2Fdashboard');

  const loginPage = await request(app).get('/login');
  assert.equal(loginPage.status, 200);
  assert.match(loginPage.headers['content-type'], /text\/html/);

  const registerPage = await request(app).get('/register');
  assert.equal(registerPage.status, 200);

  const twoFactorPage = await request(app).get('/two-factor');
  assert.equal(twoFactorPage.status, 302);
  assert.equal(twoFactorPage.headers.location, '/login?expired=1');
});

test('returns a minimal, non-sensitive dashboard payload for the signed-in user', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const user = uniqueUser();
  const registration = await register(agent, user);
  assert.equal(registration.response.status, 201);

  const beforeLogin = await agent.get('/api/dashboard');
  assert.equal(beforeLogin.status, 200);
  assert.deepEqual(Object.keys(beforeLogin.body.user).sort(), [
    'createdAt',
    'email',
    'fullName',
    'id',
    'lastLoginAt',
    'twoFactorEnabled',
    'username'
  ]);
  assert.equal(beforeLogin.body.user.email, user.email.toLowerCase());
  assert.equal(beforeLogin.body.user.lastLoginAt, null);
  assert.equal(beforeLogin.body.user.twoFactorEnabled, false);
  assert.ok(!Number.isNaN(Date.parse(beforeLogin.body.user.createdAt)));
  assert.ok(beforeLogin.body.securityEvents.some((event) => event.type === 'account_created'));

  const serialized = JSON.stringify(beforeLogin.body);
  assert.ok(!serialized.includes('password'));
  assert.ok(!serialized.includes('two_factor_secret'));
  assert.ok(!serialized.includes(user.password));

  await logout(agent, registration.csrfToken);
  const signedIn = await login(agent, user.username, user.password);
  assert.equal(signedIn.response.status, 200);

  const afterLogin = await agent.get('/api/dashboard');
  assert.equal(afterLogin.status, 200);
  assert.ok(!Number.isNaN(Date.parse(afterLogin.body.user.lastLoginAt)));
  assert.ok(!Number.isNaN(Date.parse(afterLogin.body.session.expiresAt)));
  assert.ok(Date.parse(afterLogin.body.session.expiresAt) > Date.now());
  assert.ok(afterLogin.body.securityEvents.some((event) => event.type === 'login_success'));
  assert.ok(afterLogin.body.securityEvents.length <= 8);
  assert.ok(
    afterLogin.body.securityEvents.every(
      (event) => typeof event.type === 'string' && !Number.isNaN(Date.parse(event.createdAt))
    )
  );
});

test('serves the protected dashboard shell only to authenticated sessions', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const agent = request.agent(app);
  const registration = await register(agent, uniqueUser());
  assert.equal(registration.response.status, 201);

  const page = await agent.get('/dashboard');
  assert.equal(page.status, 200);
  assert.match(page.headers['content-type'], /text\/html/);
  assert.match(page.text, /Security console/);
  assert.match(page.text, /data-app-main/);
  assert.equal(page.headers['cache-control'], 'no-store, no-cache, must-revalidate, private');

  const loginPage = await agent.get('/login');
  assert.equal(loginPage.status, 302);
  assert.equal(loginPage.headers.location, '/dashboard');

  const registerPage = await agent.get('/register');
  assert.equal(registerPage.status, 302);
  assert.equal(registerPage.headers.location, '/dashboard');
});

test('does not expose page HTML files through static paths', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  for (const file of ['/dashboard.html', '/login.html', '/register.html', '/index.html']) {
    const response = await request(app).get(file);
    assert.equal(response.status, 404, `${file} should not be directly reachable`);
  }

  const stylesheet = await request(app).get('/css/styles.css');
  assert.equal(stylesheet.status, 200);
  assert.match(stylesheet.headers['content-type'], /text\/css/);

  const script = await request(app).get('/js/common.js');
  assert.equal(script.status, 200);
  assert.match(script.headers['content-type'], /javascript/);

  const logo = await request(app).get('/images/logo-mark.svg');
  assert.equal(logo.status, 200);
  assert.match(logo.headers['content-type'], /image\/svg\+xml/);
});

test('renders a designed 404 page and JSON for unknown API routes', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const page = await request(app).get('/this-does-not-exist');
  assert.equal(page.status, 404);
  assert.match(page.headers['content-type'], /text\/html/);
  assert.match(page.text, /Page not found/);

  const api = await request(app).get('/api/this-does-not-exist');
  assert.equal(api.status, 404);
  assert.equal(api.body.code, 'NOT_FOUND');
  assert.equal(api.body.message, 'The requested resource was not found.');
});

test('creates the expected database constraints and indexes', async (t) => {
  const app = createTestApp();
  t.after(() => app.locals.close());

  const columns = app.locals.db.prepare('PRAGMA table_info(users)').all();
  const columnNames = columns.map((column) => column.name);
  assert.ok(columnNames.includes('password_hash'));
  assert.ok(!columnNames.includes('password'));

  const userIndexes = app.locals.db.prepare('PRAGMA index_list(users)').all();
  const uniqueIndexes = userIndexes.filter((index) => index.unique === 1);
  assert.ok(uniqueIndexes.length >= 2, 'email and username must have unique indexes');

  const sessionIndexes = app.locals.db.prepare('PRAGMA index_list(sessions)').all();
  assert.ok(sessionIndexes.some((index) => index.name === 'idx_sessions_expire'));

  const recoveryForeignKeys = app.locals.db.prepare('PRAGMA foreign_key_list(recovery_codes)').all();
  assert.ok(
    recoveryForeignKeys.some(
      (key) => key.table === 'users' && key.on_delete.toUpperCase() === 'CASCADE'
    )
  );
});
