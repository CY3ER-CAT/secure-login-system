'use strict';

const crypto = require('crypto');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const ROOT_DIR = path.join(__dirname, '..');

function toInteger(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function toBoolean(value, fallback = false) {
  if (value === undefined) return fallback;
  return ['1', 'true', 'yes', 'on'].includes(String(value).toLowerCase());
}

function assertHexKey(name, value) {
  if (!/^[a-f0-9]{64}$/i.test(value || '')) {
    throw new Error(`${name} must be a 64-character hexadecimal string (32 bytes).`);
  }
  return value;
}

/**
 * Build the runtime configuration from environment variables.
 * Explicit overrides are used by the automated test suite.
 */
function loadConfig(overrides = {}) {
  const nodeEnv = overrides.nodeEnv || process.env.NODE_ENV || 'development';
  const isProduction = nodeEnv === 'production';
  const isTest = nodeEnv === 'test';

  const generatedSecrets = {};

  function secret(name, bytes, overrideKey) {
    if (overrides[overrideKey]) return overrides[overrideKey];
    const value = process.env[name];
    if (value) return value;
    if (isProduction) {
      throw new Error(`${name} is required in production. See .env.example.`);
    }
    generatedSecrets[name] = crypto.randomBytes(bytes).toString('hex');
    return generatedSecrets[name];
  }

  const sessionSecret = secret('SESSION_SECRET', 48, 'sessionSecret');
  if (sessionSecret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters long.');
  }

  const twoFactorKey = assertHexKey(
    'TWO_FACTOR_ENCRYPTION_KEY',
    secret('TWO_FACTOR_ENCRYPTION_KEY', 32, 'twoFactorEncryptionKey')
  );
  const recoveryPepper = secret('RECOVERY_CODE_PEPPER', 32, 'recoveryCodePepper');

  const rawDatabasePath =
    overrides.databasePath ||
    process.env.DATABASE_PATH ||
    'database/secure-login.sqlite';
  const databasePath =
    rawDatabasePath === ':memory:' ? rawDatabasePath : path.resolve(ROOT_DIR, rawDatabasePath);

  const config = {
    rootDir: ROOT_DIR,
    publicDir: path.join(ROOT_DIR, 'public'),
    nodeEnv,
    isProduction,
    isTest,
    port: toInteger(overrides.port || process.env.PORT, 3000),
    trustProxy: overrides.trustProxy ?? toBoolean(process.env.TRUST_PROXY, false),
    databasePath,
    session: {
      name: overrides.sessionName || process.env.SESSION_COOKIE_NAME || 'sls.sid',
      secret: sessionSecret,
      ttlMs:
        overrides.sessionTtlMs ||
        toInteger(process.env.SESSION_TTL_MINUTES, 30) * 60 * 1000,
      storeCleanupMs: isTest ? 60 * 1000 : 15 * 60 * 1000
    },
    bcryptRounds: toInteger(
      overrides.bcryptRounds || process.env.BCRYPT_ROUNDS,
      isTest ? 4 : 12
    ),
    twoFactor: {
      issuer: overrides.twoFactorIssuer || process.env.TWO_FACTOR_ISSUER || 'Secure Login System',
      encryptionKey: twoFactorKey,
      recoveryPepper,
      recoveryCodeCount: 10,
      pendingTtlMs: 5 * 60 * 1000
    },
    limits: {
      loginWindowMs:
        overrides.loginWindowMs ||
        toInteger(process.env.LOGIN_RATE_LIMIT_WINDOW_MINUTES, 15) * 60 * 1000,
      loginMax: toInteger(
        overrides.loginRateLimitMax || process.env.LOGIN_RATE_LIMIT_MAX,
        5
      ),
      registerMax: toInteger(
        overrides.registerRateLimitMax || process.env.REGISTER_RATE_LIMIT_MAX,
        5
      ),
      twoFactorMax: toInteger(
        overrides.twoFactorRateLimitMax || process.env.TWO_FACTOR_RATE_LIMIT_MAX,
        10
      ),
      apiMax: toInteger(overrides.apiRateLimitMax || process.env.API_RATE_LIMIT_MAX, 300),
      apiWindowMs: 15 * 60 * 1000,
      accountLockThreshold: toInteger(
        overrides.accountLockThreshold || process.env.ACCOUNT_LOCK_THRESHOLD,
        5
      ),
      accountLockMs:
        toInteger(overrides.accountLockMinutes || process.env.ACCOUNT_LOCK_MINUTES, 15) *
        60 *
        1000
    },
    generatedSecrets
  };

  if (!isProduction && Object.keys(generatedSecrets).length > 0) {
    // One-time warning; never print the values themselves.
    console.warn(
      '[config] Using ephemeral development secrets. Copy .env.example to .env for persistent configuration.'
    );
  }

  return config;
}

module.exports = { loadConfig, ROOT_DIR };
