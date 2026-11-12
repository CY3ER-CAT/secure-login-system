'use strict';

const session = require('express-session');

/**
 * A small, production-shaped express-session store backed by SQLite.
 * Session data never leaves the server; the browser only holds a signed ID.
 */
class SQLiteSessionStore extends session.Store {
  constructor(db, { cleanupIntervalMs = 15 * 60 * 1000 } = {}) {
    super();

    this.db = db;
    this.getStatement = db.prepare(
      'SELECT sess FROM sessions WHERE sid = ? AND expire > ?'
    );
    this.setStatement = db.prepare(
      `INSERT INTO sessions (sid, sess, expire) VALUES (?, ?, ?)
       ON CONFLICT(sid) DO UPDATE SET sess = excluded.sess, expire = excluded.expire`
    );
    this.destroyStatement = db.prepare('DELETE FROM sessions WHERE sid = ?');
    this.touchStatement = db.prepare('UPDATE sessions SET expire = ? WHERE sid = ?');
    this.cleanupStatement = db.prepare('DELETE FROM sessions WHERE expire <= ?');
    this.lengthStatement = db.prepare(
      'SELECT COUNT(*) AS count FROM sessions WHERE expire > ?'
    );
    this.clearStatement = db.prepare('DELETE FROM sessions');

    this.cleanupTimer = setInterval(() => this.cleanup(), cleanupIntervalMs);
    if (typeof this.cleanupTimer.unref === 'function') {
      this.cleanupTimer.unref();
    }
  }

  cleanup() {
    try {
      this.cleanupStatement.run(Date.now());
    } catch (error) {
      // The database may already be closed while the process is shutting down.
      if (!/database is closed/i.test(error.message)) {
        console.error('[session-store] Cleanup failed:', error.message);
      }
    }
  }

  get(sid, callback) {
    try {
      const row = this.getStatement.get(sid, Date.now());
      if (!row) return callback(null, null);
      return callback(null, JSON.parse(row.sess));
    } catch (error) {
      return callback(error);
    }
  }

  set(sid, sess, callback) {
    try {
      const expires = sess?.cookie?.expires;
      const expire = expires ? new Date(expires).getTime() : Date.now() + 24 * 60 * 60 * 1000;
      this.setStatement.run(sid, JSON.stringify(sess), expire);
      return callback?.(null);
    } catch (error) {
      return callback?.(error);
    }
  }

  touch(sid, sess, callback) {
    try {
      const expires = sess?.cookie?.expires;
      if (expires) {
        this.touchStatement.run(new Date(expires).getTime(), sid);
      }
      return callback?.(null);
    } catch (error) {
      return callback?.(error);
    }
  }

  destroy(sid, callback) {
    try {
      this.destroyStatement.run(sid);
      return callback?.(null);
    } catch (error) {
      return callback?.(error);
    }
  }

  length(callback) {
    try {
      const row = this.lengthStatement.get(Date.now());
      return callback(null, row.count);
    } catch (error) {
      return callback(error);
    }
  }

  clear(callback) {
    try {
      this.clearStatement.run();
      return callback?.(null);
    } catch (error) {
      return callback?.(error);
    }
  }

  close() {
    clearInterval(this.cleanupTimer);
  }
}

module.exports = { SQLiteSessionStore };
