'use strict';

const express = require('express');

function createDashboardRouter({ db, auth }) {
  const router = express.Router();

  const recentEvents = db.prepare(`
    SELECT event_type, created_at
    FROM security_events
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 8
  `);

  router.get('/dashboard', auth.requireAuthApi, (req, res) => {
    const user = req.user;
    const sessionExpiresAt = req.session?.cookie?.expires
      ? new Date(req.session.cookie.expires).toISOString()
      : null;

    return res.json({
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        username: user.username,
        twoFactorEnabled: Boolean(user.two_factor_enabled),
        createdAt: user.created_at,
        lastLoginAt: user.last_login_at
      },
      session: {
        expiresAt: sessionExpiresAt
      },
      securityEvents: recentEvents.all(user.id).map((event) => ({
        type: event.event_type,
        createdAt: event.created_at
      }))
    });
  });

  return router;
}

module.exports = { createDashboardRouter };
