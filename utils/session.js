'use strict';

/**
 * Promise wrappers around express-session callbacks.
 * Keeping these in one place makes the auth flows easier to reason about.
 */

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => (error ? reject(error) : resolve()));
  });
}

function saveSession(req) {
  return new Promise((resolve, reject) => {
    req.session.save((error) => (error ? reject(error) : resolve()));
  });
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    if (!req.session) return resolve();
    return req.session.destroy((error) => (error ? reject(error) : resolve()));
  });
}

module.exports = { regenerateSession, saveSession, destroySession };
