'use strict';

/**
 * Authentication and route-protection middleware.
 * User records are loaded from the database on every protected request so a
 * deleted or modified account cannot keep using an old session.
 */
function createAuthMiddleware({ db, config }) {
  const findUser = db.prepare(`
    SELECT id, full_name, email, username, two_factor_enabled, created_at, last_login_at
    FROM users
    WHERE id = ?
  `);

  function loadUser(req, res, next) {
    if (!req.session?.userId) return next();

    const user = findUser.get(req.session.userId);
    if (!user) {
      // The account was deleted. Replace the stale session so later middleware
      // (notably CSRF protection) still has a valid session object to work with.
      return req.session.regenerate((error) => (error ? next(error) : next()));
    }

    req.user = user;
    return next();
  }

  function requireAuthApi(req, res, next) {
    if (!req.user) {
      return res.status(401).json({
        code: 'UNAUTHENTICATED',
        message: 'Authentication required. Please sign in.'
      });
    }
    return next();
  }

  function requireAuthPage(req, res, next) {
    if (!req.user) {
      const nextPath = req.path.startsWith('/dashboard') ? req.path : '/dashboard';
      return res.redirect(302, `/login?next=${encodeURIComponent(nextPath)}`);
    }
    return next();
  }

  function redirectIfAuthenticatedPage(req, res, next) {
    if (req.user) return res.redirect(302, '/dashboard');
    return next();
  }

  function pendingTwoFactorIsValid(req) {
    return Boolean(
      req.session?.pending2faUserId &&
        req.session?.pending2faAt &&
        Date.now() - req.session.pending2faAt < config.twoFactor.pendingTtlMs
    );
  }

  function requirePendingTwoFactorApi(req, res, next) {
    if (!pendingTwoFactorIsValid(req)) {
      return res.status(401).json({
        code: 'TWO_FACTOR_SESSION_EXPIRED',
        message: 'Your verification session expired. Please sign in again.'
      });
    }
    return next();
  }

  function requirePendingTwoFactorPage(req, res, next) {
    if (req.user) return res.redirect(302, '/dashboard');
    if (!pendingTwoFactorIsValid(req)) {
      return res.redirect(302, '/login?expired=1');
    }
    return next();
  }

  return {
    loadUser,
    requireAuthApi,
    requireAuthPage,
    redirectIfAuthenticatedPage,
    requirePendingTwoFactorApi,
    requirePendingTwoFactorPage,
    pendingTwoFactorIsValid
  };
}

module.exports = { createAuthMiddleware };
