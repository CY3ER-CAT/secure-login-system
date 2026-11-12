'use strict';

const express = require('express');
const path = require('path');
const { noStore } = require('../middleware/security');

function createPagesRouter({ config, auth }) {
  const router = express.Router();

  function sendPage(res, fileName) {
    res.sendFile(path.join(config.publicDir, fileName));
  }

  router.get('/', (req, res) => sendPage(res, 'index.html'));

  router.get('/login', auth.redirectIfAuthenticatedPage, noStore, (req, res) =>
    sendPage(res, 'login.html')
  );

  router.get('/register', auth.redirectIfAuthenticatedPage, noStore, (req, res) =>
    sendPage(res, 'register.html')
  );

  router.get('/two-factor', auth.requirePendingTwoFactorPage, noStore, (req, res) =>
    sendPage(res, 'two-factor.html')
  );

  router.get('/dashboard', auth.requireAuthPage, noStore, (req, res) =>
    sendPage(res, 'dashboard.html')
  );

  return router;
}

module.exports = { createPagesRouter };
