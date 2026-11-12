'use strict';

const path = require('path');
const express = require('express');
const helmet = require('helmet');

const { loadConfig } = require('./config/env');
const { createDatabase } = require('./config/database');
const { SQLiteSessionStore } = require('./config/SQLiteSessionStore');
const { createSessionMiddleware } = require('./config/session');
const { createPasswordService } = require('./utils/password');
const { createCryptoService } = require('./utils/crypto');
const { createTotpService } = require('./utils/totp');
const { createAuthMiddleware } = require('./middleware/auth');
const {
  createRateLimiters,
  createCsrf,
  securityHeaders,
  noStore,
  requestLogger
} = require('./middleware/security');
const { createAuthRouter } = require('./routes/auth');
const { createDashboardRouter } = require('./routes/dashboard');
const { createPagesRouter } = require('./routes/pages');

/**
 * Build the Express application.
 *
 * A factory (instead of a module-level singleton) keeps the app testable:
 * every test can use an isolated SQLite database, short session TTLs and a
 * low bcrypt work factor without touching production configuration.
 */
function createApp(overrides = {}) {
  const config = loadConfig(overrides);
  const db = overrides.db || createDatabase(config.databasePath);
  const store = new SQLiteSessionStore(db, {
    cleanupIntervalMs: config.session.storeCleanupMs
  });

  const passwordService = createPasswordService(config.bcryptRounds);
  const cryptoService = createCryptoService({
    encryptionKey: config.twoFactor.encryptionKey,
    recoveryPepper: config.twoFactor.recoveryPepper,
    recoveryCodeCount: config.twoFactor.recoveryCodeCount
  });
  const totpService = createTotpService({ issuer: config.twoFactor.issuer });

  const auth = createAuthMiddleware({ db, config });
  const limiters = createRateLimiters(config);
  const csrf = createCsrf();

  const app = express();

  app.disable('x-powered-by');
  if (config.trustProxy) {
    app.set('trust proxy', 1);
  }

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'self'"],
          baseUri: ["'self'"],
          fontSrc: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
          imgSrc: ["'self'", 'data:'],
          objectSrc: ["'none'"],
          scriptSrc: ["'self'"],
          scriptSrcAttr: ["'none'"],
          styleSrc: ["'self'"],
          styleSrcAttr: ["'none'"],
          connectSrc: ["'self'"],
          manifestSrc: ["'self'"],
          workerSrc: ["'self'"],
          ...(config.isProduction ? { upgradeInsecureRequests: [] } : {})
        }
      },
      crossOriginEmbedderPolicy: false,
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      frameguard: { action: 'deny' },
      hsts: config.isProduction
        ? { maxAge: 15552000, includeSubDomains: true, preload: false }
        : false,
      referrerPolicy: { policy: 'no-referrer' }
    })
  );
  app.use(securityHeaders);

  app.use(express.json({ limit: '32kb', strict: true }));

  app.use(createSessionMiddleware(config, store));

  // Static assets are served from explicit, non-HTML directories. Page HTML is
  // only ever sent by the page router, so protected pages cannot be reached by
  // requesting their .html file directly.
  const staticOptions = {
    fallthrough: true,
    etag: true,
    maxAge: config.isProduction ? '1h' : 0,
    dotfiles: 'deny',
    index: false
  };
  for (const directory of ['css', 'js', 'images']) {
    app.use(
      `/${directory}`,
      express.static(path.join(config.publicDir, directory), staticOptions)
    );
  }

  if (!config.isTest) {
    app.use(requestLogger);
  }

  app.use(auth.loadUser);

  app.use('/api', noStore);

  // Broad per-IP ceiling for the API surface. Route-specific limiters (login,
  // registration, 2FA) still enforce tighter budgets on sensitive endpoints.
  app.use('/api', limiters.apiLimiter);

  // Synchroniser-token CSRF protection for every state-changing request.
  // GET/HEAD/OPTIONS are ignored by the library.
  app.use(csrf.csrfProtection);

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', environment: config.nodeEnv });
  });

  app.use('/api', createAuthRouter({
    db,
    config,
    passwordService,
    cryptoService,
    totpService,
    auth,
    limiters,
    csrf
  }));

  app.use('/api', createDashboardRouter({ db, auth }));

  app.use(createPagesRouter({ config, auth }));

  // 404: JSON for API clients, a designed page for browsers.
  app.use((req, res) => {
    if (req.path.startsWith('/api/') || req.path === '/api') {
      return res.status(404).json({
        code: 'NOT_FOUND',
        message: 'The requested resource was not found.'
      });
    }
    return res.status(404).sendFile(path.join(config.publicDir, '404.html'));
  });

  // Centralised error handler. Internal details are logged, never returned.
  // eslint-disable-next-line no-unused-vars
  app.use((error, req, res, next) => {
    if (res.headersSent) {
      return next(error);
    }

    const isApi =
      req.path.startsWith('/api/') ||
      req.path === '/api' ||
      req.originalUrl.startsWith('/api/');

    if (error.code === 'EBADCSRFTOKEN') {
      let csrfToken;
      try {
        csrfToken = req.session ? csrf.generateToken(req) : undefined;
      } catch {
        csrfToken = undefined;
      }
      return res.status(403).json({
        code: 'CSRF_INVALID',
        message: 'Your security token expired. Refresh the page and try again.',
        csrfToken
      });
    }

    if (error.type === 'entity.parse.failed') {
      return res.status(400).json({
        code: 'INVALID_REQUEST',
        message: 'The request body is not valid JSON.'
      });
    }

    if (error.type === 'entity.too.large') {
      return res.status(413).json({
        code: 'PAYLOAD_TOO_LARGE',
        message: 'The request body is too large.'
      });
    }

    if (!config.isTest) {
      console.error(`[error] ${req.method} ${req.path}:`, error.stack || error.message);
    }

    if (isApi) {
      return res.status(500).json({
        code: 'INTERNAL_ERROR',
        message: 'Something went wrong. Please try again.'
      });
    }

    return res.status(500).type('text/plain').send('Internal Server Error');
  });

  let closed = false;
  app.locals.config = config;
  app.locals.db = db;
  app.locals.store = store;
  app.locals.services = { passwordService, cryptoService, totpService };
  app.locals.close = function close() {
    if (closed) return;
    closed = true;
    store.close();
    if (!overrides.db) {
      db.close();
    }
  };

  return app;
}

module.exports = { createApp };
