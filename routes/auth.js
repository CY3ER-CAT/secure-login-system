'use strict';

const express = require('express');
const {
  registerValidation,
  loginValidation,
  twoFactorCodeValidation,
  setupCodeValidation,
  disableTwoFactorValidation,
  handleValidationErrors
} = require('../middleware/validation');
const {
  regenerateSession,
  saveSession,
  destroySession
} = require('../utils/session');
const { nowIso, asyncHandler } = require('../utils/http');

function publicUser(row) {
  return {
    id: row.id,
    fullName: row.full_name,
    email: row.email,
    username: row.username,
    twoFactorEnabled: Boolean(row.two_factor_enabled),
    createdAt: row.created_at,
    lastLoginAt: row.last_login_at
  };
}

function invalidCredentials(res) {
  return res.status(401).json({
    code: 'INVALID_CREDENTIALS',
    message: 'Invalid username or password.'
  });
}

function createAuthRouter({
  db,
  config,
  passwordService,
  cryptoService,
  totpService,
  auth,
  limiters,
  csrf
}) {
  const router = express.Router();

  const findUserByLogin = db.prepare(`
    SELECT *
    FROM users
    WHERE email = ? COLLATE NOCASE OR username = ? COLLATE NOCASE
    LIMIT 1
  `);
  const findUserByEmail = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE');
  const findUserByUsername = db.prepare(
    'SELECT id FROM users WHERE username = ? COLLATE NOCASE'
  );
  const findUserById = db.prepare('SELECT * FROM users WHERE id = ?');
  const insertUser = db.prepare(`
    INSERT INTO users (full_name, email, username, password_hash, created_at, updated_at)
    VALUES (@fullName, @email, @username, @passwordHash, @now, @now)
  `);
  const resetLoginFailures = db.prepare(`
    UPDATE users
    SET failed_login_attempts = 0, locked_until = NULL, updated_at = ?
    WHERE id = ?
  `);
  const recordLoginFailure = db.prepare(`
    UPDATE users
    SET failed_login_attempts = ?, locked_until = ?, updated_at = ?
    WHERE id = ?
  `);
  const recordLoginSuccess = db.prepare(`
    UPDATE users
    SET failed_login_attempts = 0,
        locked_until = NULL,
        last_login_at = ?,
        updated_at = ?
    WHERE id = ?
  `);
  const insertSecurityEvent = db.prepare(`
    INSERT INTO security_events (user_id, event_type, created_at)
    VALUES (?, ?, ?)
  `);
  const unusedRecoveryCodes = db.prepare(`
    SELECT id, code_hash
    FROM recovery_codes
    WHERE user_id = ? AND used_at IS NULL
  `);
  const markRecoveryCodeUsed = db.prepare(`
    UPDATE recovery_codes
    SET used_at = ?
    WHERE id = ?
  `);
  const deleteRecoveryCodes = db.prepare('DELETE FROM recovery_codes WHERE user_id = ?');
  const insertRecoveryCode = db.prepare(`
    INSERT INTO recovery_codes (user_id, code_hash, created_at)
    VALUES (?, ?, ?)
  `);
  const enableTwoFactor = db.prepare(`
    UPDATE users
    SET two_factor_enabled = 1, two_factor_secret = ?, updated_at = ?
    WHERE id = ?
  `);
  const disableTwoFactor = db.prepare(`
    UPDATE users
    SET two_factor_enabled = 0, two_factor_secret = NULL, updated_at = ?
    WHERE id = ?
  `);

  const replaceRecoveryCodes = db.transaction((userId, codes) => {
    deleteRecoveryCodes.run(userId);
    const createdAt = nowIso();
    for (const code of codes) {
      insertRecoveryCode.run(userId, cryptoService.hashRecoveryCode(code), createdAt);
    }
  });

  function logEvent(userId, eventType) {
    insertSecurityEvent.run(userId, eventType, nowIso());
  }

  function verifyRecoveryCode(userId, code, { consume = true } = {}) {
    const rows = unusedRecoveryCodes.all(userId);
    const match = cryptoService.verifyRecoveryCode(
      code,
      rows.map((row) => row.code_hash)
    );
    if (!match) return false;
    if (consume) {
      const row = rows.find((entry) => entry.code_hash === match);
      if (!row) return false;
      markRecoveryCodeUsed.run(nowIso(), row.id);
    }
    return true;
  }

  function verifySecondFactor(user, code, { consumeRecovery = true } = {}) {
    if (!user.two_factor_secret) return false;
    if (/^\d{6}$/.test(code)) {
      const secret = cryptoService.decryptSecret(user.two_factor_secret);
      return totpService.verify(code, secret);
    }
    return verifyRecoveryCode(user.id, code, { consume: consumeRecovery });
  }

  async function establishAuthenticatedSession(req, userId) {
    await regenerateSession(req);
    req.session.userId = userId;
    const csrfToken = csrf.generateToken(req);
    await saveSession(req);
    return csrfToken;
  }

  router.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: csrf.generateToken(req) });
  });

  router.get('/auth/me', (req, res) => {
    if (!req.user) {
      return res.status(401).json({
        code: 'UNAUTHENTICATED',
        message: 'Authentication required. Please sign in.'
      });
    }
    return res.json({ user: req.user });
  });

  router.post(
    '/auth/register',
    limiters.registerLimiter,
    registerValidation,
    handleValidationErrors,
    asyncHandler(async (req, res) => {
      const { full_name: fullName, email, username, password } = req.body;

      if (findUserByEmail.get(email)) {
        return res.status(409).json({
          code: 'EMAIL_IN_USE',
          message: 'An account with this email address already exists.',
          errors: { email: 'An account with this email address already exists.' }
        });
      }
      if (findUserByUsername.get(username)) {
        return res.status(409).json({
          code: 'USERNAME_IN_USE',
          message: 'That username is already taken.',
          errors: { username: 'That username is already taken.' }
        });
      }

      const passwordHash = await passwordService.hash(password);
      let userId;
      try {
        const result = insertUser.run({
          fullName,
          email,
          username,
          passwordHash,
          now: nowIso()
        });
        userId = Number(result.lastInsertRowid);
      } catch (error) {
        // A concurrent registration can still hit the unique index.
        if (/UNIQUE constraint failed: users\.email/i.test(error.message)) {
          return res.status(409).json({
            code: 'EMAIL_IN_USE',
            message: 'An account with this email address already exists.',
            errors: { email: 'An account with this email address already exists.' }
          });
        }
        if (/UNIQUE constraint failed: users\.username/i.test(error.message)) {
          return res.status(409).json({
            code: 'USERNAME_IN_USE',
            message: 'That username is already taken.',
            errors: { username: 'That username is already taken.' }
          });
        }
        throw error;
      }

      const csrfToken = await establishAuthenticatedSession(req, userId);
      logEvent(userId, 'account_created');

      const user = findUserById.get(userId);
      return res.status(201).json({
        message: 'Account created successfully.',
        user: publicUser(user),
        csrfToken
      });
    })
  );

  router.post(
    '/auth/login',
    limiters.loginLimiter,
    loginValidation,
    handleValidationErrors,
    asyncHandler(async (req, res) => {
      const identifier = String(req.body.identifier).trim().toLowerCase();
      const password = req.body.password;

      const user = findUserByLogin.get(identifier, identifier);
      if (!user) {
        await passwordService.verifyDummy(password);
        return invalidCredentials(res);
      }

      const lockedUntil = user.locked_until ? Date.parse(user.locked_until) : 0;
      if (lockedUntil && lockedUntil > Date.now()) {
        return res.status(429).json({
          code: 'ACCOUNT_LOCKED',
          message:
            'Too many sign-in attempts. Please wait a few minutes before trying again.'
        });
      }

      const passwordMatches = await passwordService.verify(password, user.password_hash);
      if (!passwordMatches) {
        const attempts = user.failed_login_attempts + 1;
        const shouldLock = attempts >= config.limits.accountLockThreshold;
        const lockUntil = shouldLock
          ? new Date(Date.now() + config.limits.accountLockMs).toISOString()
          : null;
        recordLoginFailure.run(attempts, lockUntil, nowIso(), user.id);

        if (shouldLock) {
          logEvent(user.id, 'account_locked');
          return res.status(429).json({
            code: 'ACCOUNT_LOCKED',
            message:
              'Too many sign-in attempts. Please wait a few minutes before trying again.'
          });
        }
        return invalidCredentials(res);
      }

      resetLoginFailures.run(nowIso(), user.id);

      if (user.two_factor_enabled) {
        await regenerateSession(req);
        req.session.pending2faUserId = user.id;
        req.session.pending2faAt = Date.now();
        const csrfToken = csrf.generateToken(req);
        await saveSession(req);
        return res.json({
          message: 'Password verified. Enter your authenticator code.',
          twoFactorRequired: true,
          csrfToken
        });
      }

      recordLoginSuccess.run(nowIso(), nowIso(), user.id);
      const csrfToken = await establishAuthenticatedSession(req, user.id);
      logEvent(user.id, 'login_success');

      return res.json({
        message: 'Signed in successfully.',
        user: publicUser(findUserById.get(user.id)),
        csrfToken
      });
    })
  );

  router.post(
    '/auth/login/2fa',
    auth.requirePendingTwoFactorApi,
    limiters.twoFactorLimiter,
    twoFactorCodeValidation,
    handleValidationErrors,
    asyncHandler(async (req, res) => {
      const user = findUserById.get(req.session.pending2faUserId);
      if (!user || !user.two_factor_enabled) {
        return res.status(401).json({
          code: 'TWO_FACTOR_SESSION_EXPIRED',
          message: 'Your verification session expired. Please sign in again.'
        });
      }

      const code = req.body.code;
      const usedRecoveryCode = !/^\d{6}$/.test(code);
      const valid = verifySecondFactor(user, code);
      if (!valid) {
        return res.status(401).json({
          code: 'INVALID_CODE',
          message: 'That verification code is not valid. Please try again.'
        });
      }

      recordLoginSuccess.run(nowIso(), nowIso(), user.id);
      const csrfToken = await establishAuthenticatedSession(req, user.id);
      logEvent(user.id, 'login_success');
      if (usedRecoveryCode) {
        logEvent(user.id, 'recovery_code_used');
      }

      return res.json({
        message: 'Signed in successfully.',
        user: publicUser(findUserById.get(user.id)),
        csrfToken
      });
    })
  );

  router.post(
    '/auth/logout',
    asyncHandler(async (req, res) => {
      const userId = req.session?.userId;
      await destroySession(req);
      res.clearCookie(config.session.name, {
        path: '/',
        httpOnly: true,
        secure: config.isProduction,
        sameSite: 'lax'
      });
      if (userId) logEvent(userId, 'logout');
      return res.json({ message: 'Signed out successfully.' });
    })
  );

  router.post(
    '/2fa/setup',
    auth.requireAuthApi,
    asyncHandler(async (req, res) => {
      const user = findUserById.get(req.user.id);
      if (user.two_factor_enabled) {
        return res.status(409).json({
          code: 'TWO_FACTOR_ALREADY_ENABLED',
          message: 'Two-factor authentication is already enabled for this account.'
        });
      }

      const secret = totpService.generateSecret();
      const otpauthUrl = totpService.otpauthUrl(user.email, secret);
      const qrCodeDataUrl = await totpService.qrDataUrl(otpauthUrl);

      req.session.pending2faSetupSecret = cryptoService.encryptSecret(secret);
      req.session.pending2faSetupAt = Date.now();
      await saveSession(req);

      return res.json({
        message: 'Scan the QR code with your authenticator app.',
        secret,
        otpauthUrl,
        qrCodeDataUrl
      });
    })
  );

  router.post(
    '/2fa/enable',
    auth.requireAuthApi,
    limiters.twoFactorLimiter,
    setupCodeValidation,
    handleValidationErrors,
    asyncHandler(async (req, res) => {
      const user = findUserById.get(req.user.id);
      if (user.two_factor_enabled) {
        return res.status(409).json({
          code: 'TWO_FACTOR_ALREADY_ENABLED',
          message: 'Two-factor authentication is already enabled for this account.'
        });
      }

      const pendingSecret = req.session.pending2faSetupSecret;
      const pendingAt = req.session.pending2faSetupAt;
      if (!pendingSecret || !pendingAt || Date.now() - pendingAt > config.twoFactor.pendingTtlMs) {
        return res.status(401).json({
          code: 'TWO_FACTOR_SETUP_EXPIRED',
          message: 'Your setup session expired. Start the setup again.'
        });
      }

      let secret;
      try {
        secret = cryptoService.decryptSecret(pendingSecret);
      } catch {
        return res.status(401).json({
          code: 'TWO_FACTOR_SETUP_EXPIRED',
          message: 'Your setup session expired. Start the setup again.'
        });
      }

      if (!totpService.verify(req.body.code, secret)) {
        return res.status(401).json({
          code: 'INVALID_CODE',
          message: 'That code is not valid. Check your authenticator app and try again.'
        });
      }

      const recoveryCodes = cryptoService.generateRecoveryCodes();
      const enableTransaction = db.transaction(() => {
        enableTwoFactor.run(
          cryptoService.encryptSecret(secret),
          nowIso(),
          user.id
        );
        replaceRecoveryCodes(user.id, recoveryCodes);
      });
      enableTransaction();

      delete req.session.pending2faSetupSecret;
      delete req.session.pending2faSetupAt;
      await saveSession(req);

      logEvent(user.id, 'two_factor_enabled');
      return res.json({
        message: 'Two-factor authentication enabled.',
        twoFactorEnabled: true,
        recoveryCodes
      });
    })
  );

  router.post(
    '/2fa/disable',
    auth.requireAuthApi,
    limiters.twoFactorLimiter,
    disableTwoFactorValidation,
    handleValidationErrors,
    asyncHandler(async (req, res) => {
      const user = findUserById.get(req.user.id);
      if (!user.two_factor_enabled) {
        return res.status(409).json({
          code: 'TWO_FACTOR_NOT_ENABLED',
          message: 'Two-factor authentication is not enabled for this account.'
        });
      }

      const passwordMatches = await passwordService.verify(
        req.body.password,
        user.password_hash
      );
      if (!passwordMatches) {
        return res.status(401).json({
          code: 'INVALID_PASSWORD',
          message: 'Your password is incorrect.'
        });
      }

      if (!verifySecondFactor(user, req.body.code)) {
        return res.status(401).json({
          code: 'INVALID_CODE',
          message: 'That verification code is not valid.'
        });
      }

      const disableTransaction = db.transaction(() => {
        disableTwoFactor.run(nowIso(), user.id);
        deleteRecoveryCodes.run(user.id);
      });
      disableTransaction();

      logEvent(user.id, 'two_factor_disabled');
      return res.json({
        message: 'Two-factor authentication disabled.',
        twoFactorEnabled: false
      });
    })
  );

  router.post(
    '/2fa/recovery-codes',
    auth.requireAuthApi,
    limiters.twoFactorLimiter,
    disableTwoFactorValidation,
    handleValidationErrors,
    asyncHandler(async (req, res) => {
      const user = findUserById.get(req.user.id);
      if (!user.two_factor_enabled) {
        return res.status(409).json({
          code: 'TWO_FACTOR_NOT_ENABLED',
          message: 'Two-factor authentication is not enabled for this account.'
        });
      }

      const passwordMatches = await passwordService.verify(
        req.body.password,
        user.password_hash
      );
      if (!passwordMatches) {
        return res.status(401).json({
          code: 'INVALID_PASSWORD',
          message: 'Your password is incorrect.'
        });
      }

      if (!verifySecondFactor(user, req.body.code)) {
        return res.status(401).json({
          code: 'INVALID_CODE',
          message: 'That verification code is not valid.'
        });
      }

      const recoveryCodes = cryptoService.generateRecoveryCodes();
      replaceRecoveryCodes(user.id, recoveryCodes);
      logEvent(user.id, 'recovery_codes_regenerated');

      return res.json({
        message: 'New recovery codes generated. Previous codes no longer work.',
        recoveryCodes
      });
    })
  );

  return router;
}

module.exports = { createAuthRouter, publicUser };
