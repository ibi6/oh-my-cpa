-- Customer portal accounts (ADR 0105).
--
-- The portal is the distribution layer: an operator hands accounts to customers,
-- and each customer issues their own gateway keys and reads their own usage.
-- These tables are numbered in a range of their own (9xx) so the fork that
-- carries them never collides with the upstream migration sequence; the runner
-- applies any unapplied version regardless of order.
--
-- Customer keys are stored as a keyed fingerprint plus a display prefix and
-- tail. The fingerprint is the same HMAC the request records carry in
-- usage_events.api_group_key, so it is both the lookup identity and the join to
-- usage; the plaintext exists only in the response that created the key and in
-- CPA's own access.api-keys list.

CREATE TABLE portal_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    -- How the account came to exist: created by the operator, redeemed from an
    -- invite, or self-registered while registration was open.
    origin TEXT NOT NULL DEFAULT 'admin' CHECK (origin IN ('admin', 'invite', 'open')),
    max_keys INTEGER NOT NULL DEFAULT 10 CHECK (max_keys >= 0),
    note TEXT NOT NULL DEFAULT '',
    -- Raised on a password change or a disable, which ends every session that was
    -- issued under the previous value.
    auth_version INTEGER NOT NULL DEFAULT 1,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    last_login_at_ms INTEGER
);

-- Server-side sessions, so a disable or a password change ends them at once.
-- Only the SHA-256 of the cookie token is stored.
CREATE TABLE portal_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES portal_users(id) ON DELETE CASCADE,
    auth_version INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    last_seen_at_ms INTEGER NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
) WITHOUT ROWID;
CREATE INDEX idx_portal_sessions_user ON portal_sessions(user_id);
CREATE INDEX idx_portal_sessions_expiry ON portal_sessions(expires_at_ms);

-- Invite codes for the "invite" registration mode. Stored hashed like keys.
CREATE TABLE portal_invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash TEXT NOT NULL UNIQUE,
    code_prefix TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    expires_at_ms INTEGER,
    revoked_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE portal_api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES portal_users(id),
    name TEXT NOT NULL,
    -- HMAC under the "usage-api-key" purpose: equal to usage_events.api_group_key
    -- for every request this key authenticates.
    key_fingerprint TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    key_last4 TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    -- Whether CPA's access.api-keys agrees with what this row wants:
    -- pending (not yet written), synced (present and wanted), missing (wanted but
    -- absent from CPA - the plaintext is not kept, so it cannot be re-added),
    -- removed (unwanted and absent) or failed (the last write was refused).
    sync_state TEXT NOT NULL DEFAULT 'pending'
        CHECK (sync_state IN ('pending', 'synced', 'missing', 'removed', 'failed')),
    sync_error TEXT NOT NULL DEFAULT '',
    synced_at_ms INTEGER,
    expires_at_ms INTEGER,
    request_count INTEGER NOT NULL DEFAULT 0,
    last_used_at_ms INTEGER,
    created_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER
);
CREATE INDEX idx_portal_api_keys_user ON portal_api_keys(user_id, id DESC);
