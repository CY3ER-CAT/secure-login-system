'use strict';

const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { csrfSync } = require('csrf-sync');

function normalizeIdentifier(value) {
  return String(value ?? '').trim().toLowerCase().slice(0, 254);
}

function jsonRateLimitHandler(message) {
  return (req, res) => {
    res.status(429).json({ code: 'RATE_LIMITED', message });
  };
}

/**
 * Rate limiters are separate so that a burst of failed logins does not
 * interfere with normal dashboard usage, and so registration and 2FA
 * verification each have their own budget.
 */
function createRateLimiters(config) {
  const common = {
    standardHeaders: 'draft-8',
    legacyHeaders: false
  };

  const apiLimiter = rateLimit({
    ...common,
    windowMs: config.limits.apiWindowMs,
    limit: config.limits.apiMax,
    handler: jsonRateLimitHandler('Too many requests. Please slow down and try again later.')
  });

  const loginLimiter = rateLimit({
    ...common,
    windowMs: config.limits.loginWindowMs,
    limit: config.limits.loginMax,
    skipSuccessfulRequests: true,
    keyGenerator: (req) =>
      `${ipKeyGenerator(req.ip)}:${normalizeIdentifier(req.body?.identifier)}`,
    handler: jsonRateLimitHandler(
      'Too many sign-in attempts. Please wait a few minutes before trying again.'
    )
  });

  const registerLimiter = rateLimit({
    ...common,
    windowMs: config.limits.loginWindowMs,
    limit: config.limits.registerMax,
    keyGenerator: (req) => ipKeyGenerator(req.ip),
    handler: jsonRateLimitHandler(
      'Too many accounts created from this network. Please try again later.'
    )
  });

  const twoFactorLimiter = rateLimit({
    ...common,
    windowMs: config.limits.loginWindowMs,
    limit: config.limits.twoFactorMax,
    skipSuccessfulRequests: true,
    keyGenerator: (req) =>
      `${ipKeyGenerator(req.ip)}:${req.session?.pending2faUserId || req.user?.id || 'anonymous'}`,
    handler: jsonRateLimitHandler(
      'Too many verification attempts. Please wait a few minutes and try again.'
    )
  });

  return { apiLimiter, loginLimiter, registerLimiter, twoFactorLimiter };
}

function createCsrf() {
  const { generateToken, csrfSynchronisedProtection } = csrfSync({
    errorConfig: {
      statusCode: 403,
      message: 'Invalid or expired CSRF token.',
      code: 'EBADCSRFTOKEN'
    }
  });

  return {
    generateToken,
    csrfProtection: csrfSynchronisedProtection
  };
}

function securityHeaders(req, res, next) {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()'
  );
  res.setHeader('X-Permitted-Cross-Domain-Policies', 'none');
  next();
}

function noStore(req, res, next) {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
}

function requestLogger(req, res, next) {
  const startedAt = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    // Log only method, path, status and timing. Never bodies, cookies or secrets.
    console.log(
      `[http] ${req.method} ${req.path} ${res.statusCode} ${durationMs.toFixed(1)}ms`
    );
  });
  next();
}

module.exports = {
  createRateLimiters,
  createCsrf,
  securityHeaders,
  noStore,
  requestLogger,
  normalizeIdentifier
};
