'use strict';

const { authenticator } = require('otplib');
const QRCode = require('qrcode');

authenticator.options = {
  window: 1,
  step: 30
};

function createTotpService({ issuer }) {
  return {
    generateSecret() {
      return authenticator.generateSecret(20);
    },

    otpauthUrl(accountName, secret) {
      return authenticator.keyuri(accountName, issuer, secret);
    },

    async qrDataUrl(otpauthUrl) {
      return QRCode.toDataURL(otpauthUrl, {
        errorCorrectionLevel: 'M',
        margin: 1,
        width: 240,
        color: { dark: '#07101f', light: '#ffffff' }
      });
    },

    verify(token, secret) {
      if (!/^\d{6}$/.test(String(token || ''))) return false;
      try {
        return authenticator.verify({ token: String(token), secret });
      } catch {
        return false;
      }
    }
  };
}

module.exports = { createTotpService };
