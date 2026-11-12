'use strict';

const crypto = require('crypto');

const RECOVERY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const RECOVERY_GROUP_LENGTH = 5;
const RECOVERY_GROUPS = 2;

function normalizeRecoveryCode(code) {
  return String(code || '')
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
}

function createCryptoService({ encryptionKey, recoveryPepper, recoveryCodeCount = 10 }) {
  const key = Buffer.from(encryptionKey, 'hex');
  if (key.length !== 32) {
    throw new Error('Two-factor encryption key must be 32 bytes.');
  }
  if (!recoveryPepper || recoveryPepper.length < 16) {
    throw new Error('A recovery-code pepper is required.');
  }

  function encryptSecret(plaintext) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(String(plaintext), 'utf8'),
      cipher.final()
    ]);
    const tag = cipher.getAuthTag();
    return `v1:${Buffer.concat([iv, tag, ciphertext]).toString('base64')}`;
  }

  function decryptSecret(encoded) {
    if (typeof encoded !== 'string' || !encoded.startsWith('v1:')) {
      throw new Error('Unsupported secret format.');
    }
    const payload = Buffer.from(encoded.slice(3), 'base64');
    if (payload.length < 12 + 16) {
      throw new Error('Malformed encrypted secret.');
    }
    const iv = payload.subarray(0, 12);
    const tag = payload.subarray(12, 28);
    const ciphertext = payload.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  }

  function generateRecoveryCode() {
    const length = RECOVERY_GROUP_LENGTH * RECOVERY_GROUPS;
    let code = '';
    for (let i = 0; i < length; i += 1) {
      code += RECOVERY_ALPHABET[crypto.randomInt(0, RECOVERY_ALPHABET.length)];
    }
    return code.match(new RegExp(`.{1,${RECOVERY_GROUP_LENGTH}}`, 'g')).join('-');
  }

  function generateRecoveryCodes(count = recoveryCodeCount) {
    return Array.from({ length: count }, generateRecoveryCode);
  }

  function hashRecoveryCode(code) {
    return crypto
      .createHmac('sha256', recoveryPepper)
      .update(normalizeRecoveryCode(code))
      .digest('hex');
  }

  function safeEqualHex(left, right) {
    const a = Buffer.from(String(left), 'hex');
    const b = Buffer.from(String(right), 'hex');
    if (a.length === 0 || a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  function verifyRecoveryCode(code, storedHashes) {
    const digest = hashRecoveryCode(code);
    let match = null;
    for (const stored of storedHashes) {
      if (safeEqualHex(digest, stored)) {
        match = stored;
      }
    }
    return match;
  }

  return {
    encryptSecret,
    decryptSecret,
    generateRecoveryCodes,
    hashRecoveryCode,
    verifyRecoveryCode,
    normalizeRecoveryCode
  };
}

module.exports = { createCryptoService, normalizeRecoveryCode };
