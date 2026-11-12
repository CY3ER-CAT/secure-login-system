'use strict';

const session = require('express-session');

/**
 * Secure server-side session configuration.
 * - HttpOnly + SameSite=Lax cookies
 * - Secure cookies whenever the app runs in production (HTTPS)
 * - Rolling expiration with a hard cookie max-age
 */
function createSessionMiddleware(config, store) {
  return session({
    name: config.session.name,
    secret: config.session.secret,
    store,
    resave: false,
    saveUninitialized: false,
    rolling: true,
    proxy: config.trustProxy,
    unset: 'destroy',
    cookie: {
      httpOnly: true,
      secure: config.isProduction,
      sameSite: 'lax',
      maxAge: config.session.ttlMs,
      path: '/'
    }
  });
}

module.exports = { createSessionMiddleware };
