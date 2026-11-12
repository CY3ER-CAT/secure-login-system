-- Secure Login System — database schema
-- All timestamps are stored as ISO-8601 UTC strings.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name             TEXT    NOT NULL
                                CHECK (length(full_name) BETWEEN 2 AND 80),
  email                 TEXT    NOT NULL COLLATE NOCASE
                                CHECK (length(email) BETWEEN 3 AND 254),
  username              TEXT    NOT NULL COLLATE NOCASE
                                CHECK (length(username) BETWEEN 3 AND 30),
  password_hash         TEXT    NOT NULL
                                CHECK (length(password_hash) BETWEEN 50 AND 100),
  two_factor_enabled    INTEGER NOT NULL DEFAULT 0
                                CHECK (two_factor_enabled IN (0, 1)),
  two_factor_secret     TEXT,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0
                                CHECK (failed_login_attempts >= 0),
  locked_until          TEXT,
  last_login_at         TEXT,
  created_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at            TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Case-insensitive uniqueness for both login identifiers.
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique
  ON users (email COLLATE NOCASE);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_unique
  ON users (username COLLATE NOCASE);

-- Recovery codes are high-entropy values stored only as keyed hashes.
CREATE TABLE IF NOT EXISTS recovery_codes (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  code_hash   TEXT    NOT NULL,
  used_at     TEXT,
  created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_recovery_codes_user
  ON recovery_codes (user_id, used_at);

-- Small, non-sensitive audit trail shown on the dashboard.
CREATE TABLE IF NOT EXISTS security_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  event_type  TEXT    NOT NULL,
  created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_security_events_user
  ON security_events (user_id, created_at DESC);

-- Server-side session store. The cookie only contains a signed session ID.
CREATE TABLE IF NOT EXISTS sessions (
  sid     TEXT PRIMARY KEY,
  sess    TEXT    NOT NULL,
  expire  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expire
  ON sessions (expire);
