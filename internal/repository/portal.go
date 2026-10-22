package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Customer portal storage (ADR 0105). The portal's own tables live in the 9xx
// migrations; nothing here touches a table the upstream console owns except the
// read of usage_events that projects a customer's own records.

// ErrPortalConflict reports a unique-constraint clash: a username or key that
// already exists.
var ErrPortalConflict = errors.New("portal conflict")

// ErrPortalInviteInvalid reports an invite code that does not exist, was
// revoked, expired or is used up. One error for all four so a caller cannot
// probe which codes exist.
var ErrPortalInviteInvalid = errors.New("portal invite invalid")

const (
	PortalUserActive   = "active"
	PortalUserDisabled = "disabled"

	PortalKeyActive  = "active"
	PortalKeyRevoked = "revoked"

	PortalSyncPending = "pending"
	PortalSyncSynced  = "synced"
	PortalSyncMissing = "missing"
	PortalSyncRemoved = "removed"
	PortalSyncFailed  = "failed"
)

// PortalUser is one customer account.
type PortalUser struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	DisplayName   string `json:"display_name"`
	PasswordHash  string `json:"-"`
	Status        string `json:"status"`
	Origin        string `json:"origin"`
	MaxKeys       int    `json:"max_keys"`
	Note          string `json:"note"`
	AuthVersion   int64  `json:"-"`
	CreatedAtMS   int64  `json:"created_at_ms"`
	UpdatedAtMS   int64  `json:"updated_at_ms"`
	LastLoginAtMS *int64 `json:"last_login_at_ms,omitempty"`
}

// PortalUserSummary is a user row with the counts the operator's list shows.
type PortalUserSummary struct {
	PortalUser
	ActiveKeys   int    `json:"active_keys"`
	TotalKeys    int    `json:"total_keys"`
	Requests     int64  `json:"requests"`
	TotalTokens  int64  `json:"total_tokens"`
	CostNanos    int64  `json:"-"`
	LastUsedAtMS *int64 `json:"last_used_at_ms,omitempty"`
}

// PortalUserPatch names the fields an operator update changes; nil leaves a
// field alone. A new password hash or a disable raises auth_version and ends
// every session of the account in the same transaction.
type PortalUserPatch struct {
	DisplayName  *string
	Status       *string
	Note         *string
	MaxKeys      *int
	PasswordHash *string
}

// PortalKey is one customer gateway key. The plaintext is never stored.
type PortalKey struct {
	ID           int64  `json:"id"`
	UserID       int64  `json:"user_id"`
	Name         string `json:"name"`
	Fingerprint  string `json:"-"`
	Prefix       string `json:"prefix"`
	Last4        string `json:"last4"`
	Status       string `json:"status"`
	SyncState    string `json:"sync_state"`
	SyncError    string `json:"sync_error,omitempty"`
	SyncedAtMS   *int64 `json:"synced_at_ms,omitempty"`
	ExpiresAtMS  *int64 `json:"expires_at_ms,omitempty"`
	RequestCount int64  `json:"request_count"`
	LastUsedAtMS *int64 `json:"last_used_at_ms,omitempty"`
	CreatedAtMS  int64  `json:"created_at_ms"`
	RevokedAtMS  *int64 `json:"revoked_at_ms,omitempty"`
	// UserStatus is the owning account's status, joined for the sync decision.
	UserStatus string `json:"-"`
}

// Wanted reports whether CPA should accept this key at instant nowMS: it is
// active, not expired, and its account is active.
func (k PortalKey) Wanted(nowMS int64) bool {
	if k.Status != PortalKeyActive || k.UserStatus != PortalUserActive {
		return false
	}
	return k.ExpiresAtMS == nil || *k.ExpiresAtMS > nowMS
}

// PortalSession is one signed-in browser.
type PortalSession struct {
	TokenHash   string
	UserID      int64
	AuthVersion int64
	ExpiresAtMS int64
	LastSeenMS  int64
}

// PortalInvite is one invite code; the code itself is shown once.
type PortalInvite struct {
	ID          int64  `json:"id"`
	CodeHash    string `json:"-"`
	CodePrefix  string `json:"code_prefix"`
	Note        string `json:"note"`
	MaxUses     int    `json:"max_uses"`
	UsedCount   int    `json:"used_count"`
	ExpiresAtMS *int64 `json:"expires_at_ms,omitempty"`
	RevokedAtMS *int64 `json:"revoked_at_ms,omitempty"`
	CreatedAtMS int64  `json:"created_at_ms"`
}

func (r *Repository) portalDB() (*sql.DB, error) {
	if r == nil || r.SQL() == nil {
		return nil, errors.New("repository is not initialized")
	}
	return r.SQL(), nil
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique constraint")
}

func portalNullInt(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func portalIntPtr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	v := value.Int64
	return &v
}

const portalUserColumns = `id, username, display_name, password_hash, status, origin, max_keys, note,
	auth_version, created_at_ms, updated_at_ms, last_login_at_ms`

type portalScanner interface{ Scan(dest ...any) error }

func scanPortalUser(row portalScanner) (PortalUser, error) {
	var user PortalUser
	var lastLogin sql.NullInt64
	err := row.Scan(&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.Status,
		&user.Origin, &user.MaxKeys, &user.Note, &user.AuthVersion, &user.CreatedAtMS,
		&user.UpdatedAtMS, &lastLogin)
	user.LastLoginAtMS = portalIntPtr(lastLogin)
	return user, err
}

func insertPortalUser(ctx context.Context, exec interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, user PortalUser) (int64, error) {
	result, err := exec.ExecContext(ctx, `
		INSERT INTO portal_users (username, display_name, password_hash, status, origin, max_keys, note,
			auth_version, created_at_ms, updated_at_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		user.Username, user.DisplayName, user.PasswordHash, user.Status, user.Origin, user.MaxKeys,
		user.Note, user.CreatedAtMS, user.CreatedAtMS)
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrPortalConflict
		}
		return 0, fmt.Errorf("insert portal user: %w", err)
	}
	return result.LastInsertId()
}

// CreatePortalUser stores a new account and returns it.
func (r *Repository) CreatePortalUser(ctx context.Context, user PortalUser) (PortalUser, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalUser{}, err
	}
	if user.CreatedAtMS == 0 {
		user.CreatedAtMS = time.Now().UnixMilli()
	}
	id, err := insertPortalUser(ctx, db, user)
	if err != nil {
		return PortalUser{}, err
	}
	return r.GetPortalUser(ctx, id)
}

// RegisterPortalUserWithInvite redeems one use of an invite and creates the
// account in one transaction, so a code cannot be spent without an account or
// an account created on a code that was used up concurrently.
func (r *Repository) RegisterPortalUserWithInvite(ctx context.Context, user PortalUser, codeHash string, nowMS int64) (PortalUser, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalUser{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return PortalUser{}, fmt.Errorf("begin portal registration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `
		UPDATE portal_invites SET used_count = used_count + 1
		WHERE code_hash = ? AND revoked_at_ms IS NULL AND used_count < max_uses
		  AND (expires_at_ms IS NULL OR expires_at_ms > ?)`, codeHash, nowMS)
	if err != nil {
		return PortalUser{}, fmt.Errorf("redeem portal invite: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return PortalUser{}, ErrPortalInviteInvalid
	}
	if user.CreatedAtMS == 0 {
		user.CreatedAtMS = nowMS
	}
	id, err := insertPortalUser(ctx, tx, user)
	if err != nil {
		return PortalUser{}, err
	}
	if err := tx.Commit(); err != nil {
		return PortalUser{}, fmt.Errorf("commit portal registration: %w", err)
	}
	return r.GetPortalUser(ctx, id)
}

func (r *Repository) GetPortalUser(ctx context.Context, id int64) (PortalUser, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalUser{}, err
	}
	return scanPortalUser(db.QueryRowContext(ctx, `SELECT `+portalUserColumns+` FROM portal_users WHERE id = ?`, id))
}

func (r *Repository) GetPortalUserByUsername(ctx context.Context, username string) (PortalUser, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalUser{}, err
	}
	return scanPortalUser(db.QueryRowContext(ctx, `SELECT `+portalUserColumns+` FROM portal_users WHERE username = ?`, strings.TrimSpace(username)))
}

// ListPortalUsers returns every account with its key counts and lifetime usage.
func (r *Repository) ListPortalUsers(ctx context.Context) ([]PortalUserSummary, error) {
	db, err := r.portalDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT `+prefixColumns("u.", portalUserColumns)+`,
		       COALESCE((SELECT COUNT(1) FROM portal_api_keys k WHERE k.user_id = u.id AND k.status = 'active'), 0),
		       COALESCE((SELECT COUNT(1) FROM portal_api_keys k WHERE k.user_id = u.id), 0),
		       COALESCE((SELECT SUM(requests) FROM portal_usage_daily d WHERE d.user_id = u.id), 0),
		       COALESCE((SELECT SUM(total_tokens) FROM portal_usage_daily d WHERE d.user_id = u.id), 0),
		       COALESCE((SELECT SUM(cost_nanos) FROM portal_usage_daily d WHERE d.user_id = u.id), 0),
		       (SELECT MAX(last_used_at_ms) FROM portal_api_keys k WHERE k.user_id = u.id)
		FROM portal_users u ORDER BY u.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list portal users: %w", err)
	}
	defer rows.Close()
	items := []PortalUserSummary{}
	for rows.Next() {
		var item PortalUserSummary
		var lastLogin, lastUsed sql.NullInt64
		if err := rows.Scan(&item.ID, &item.Username, &item.DisplayName, &item.PasswordHash, &item.Status,
			&item.Origin, &item.MaxKeys, &item.Note, &item.AuthVersion, &item.CreatedAtMS,
			&item.UpdatedAtMS, &lastLogin, &item.ActiveKeys, &item.TotalKeys, &item.Requests,
			&item.TotalTokens, &item.CostNanos, &lastUsed); err != nil {
			return nil, fmt.Errorf("scan portal user: %w", err)
		}
		item.LastLoginAtMS = portalIntPtr(lastLogin)
		item.LastUsedAtMS = portalIntPtr(lastUsed)
		items = append(items, item)
	}
	return items, rows.Err()
}

func prefixColumns(prefix, columns string) string {
	parts := strings.Split(columns, ",")
	for i, part := range parts {
		parts[i] = prefix + strings.TrimSpace(part)
	}
	return strings.Join(parts, ", ")
}

// UpdatePortalUser applies an operator patch. A password change or a disable
// raises auth_version and deletes the account's sessions in the same
// transaction.
func (r *Repository) UpdatePortalUser(ctx context.Context, id int64, patch PortalUserPatch, nowMS int64) (PortalUser, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalUser{}, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return PortalUser{}, fmt.Errorf("begin portal user update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	current, err := scanPortalUser(tx.QueryRowContext(ctx, `SELECT `+portalUserColumns+` FROM portal_users WHERE id = ?`, id))
	if err != nil {
		return PortalUser{}, err
	}
	next := current
	endSessions := false
	if patch.DisplayName != nil {
		next.DisplayName = *patch.DisplayName
	}
	if patch.Note != nil {
		next.Note = *patch.Note
	}
	if patch.MaxKeys != nil {
		next.MaxKeys = *patch.MaxKeys
	}
	if patch.Status != nil && *patch.Status != current.Status {
		next.Status = *patch.Status
		if next.Status == PortalUserDisabled {
			endSessions = true
		}
	}
	if patch.PasswordHash != nil {
		next.PasswordHash = *patch.PasswordHash
		endSessions = true
	}
	if endSessions {
		next.AuthVersion++
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE portal_users SET display_name = ?, status = ?, note = ?, max_keys = ?, password_hash = ?,
			auth_version = ?, updated_at_ms = ? WHERE id = ?`,
		next.DisplayName, next.Status, next.Note, next.MaxKeys, next.PasswordHash, next.AuthVersion, nowMS, id); err != nil {
		return PortalUser{}, fmt.Errorf("update portal user: %w", err)
	}
	if endSessions {
		if _, err := tx.ExecContext(ctx, `DELETE FROM portal_sessions WHERE user_id = ?`, id); err != nil {
			return PortalUser{}, fmt.Errorf("end portal sessions: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return PortalUser{}, fmt.Errorf("commit portal user update: %w", err)
	}
	return r.GetPortalUser(ctx, id)
}

func (r *Repository) RecordPortalLogin(ctx context.Context, id, nowMS int64) error {
	db, err := r.portalDB()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE portal_users SET last_login_at_ms = ? WHERE id = ?`, nowMS, id)
	return err
}

// CreatePortalSession stores a session under the token's hash.
func (r *Repository) CreatePortalSession(ctx context.Context, session PortalSession, clientIP, userAgent string, nowMS int64) error {
	db, err := r.portalDB()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO portal_sessions (token_hash, user_id, auth_version, created_at_ms, expires_at_ms, last_seen_at_ms, client_ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		session.TokenHash, session.UserID, session.AuthVersion, nowMS, session.ExpiresAtMS, nowMS,
		truncateRunes(clientIP, 64), truncateRunes(userAgent, 256))
	if err != nil {
		return fmt.Errorf("create portal session: %w", err)
	}
	// Opportunistic cleanup keeps the table bounded without a separate loop.
	_, _ = db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE expires_at_ms <= ?`, nowMS)
	return nil
}

// PortalSessionUser resolves a live session to its account. A session whose
// account changed auth_version, was disabled, or that expired resolves to
// ErrNotFound.
func (r *Repository) PortalSessionUser(ctx context.Context, tokenHash string, nowMS int64) (PortalSession, PortalUser, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalSession{}, PortalUser{}, err
	}
	var session PortalSession
	row := db.QueryRowContext(ctx, `
		SELECT s.token_hash, s.user_id, s.auth_version, s.expires_at_ms, s.last_seen_at_ms, `+prefixColumns("u.", portalUserColumns)+`
		FROM portal_sessions s JOIN portal_users u ON u.id = s.user_id
		WHERE s.token_hash = ? AND s.expires_at_ms > ? AND s.auth_version = u.auth_version AND u.status = 'active'`,
		tokenHash, nowMS)
	var user PortalUser
	var lastLogin sql.NullInt64
	if err := row.Scan(&session.TokenHash, &session.UserID, &session.AuthVersion, &session.ExpiresAtMS, &session.LastSeenMS,
		&user.ID, &user.Username, &user.DisplayName, &user.PasswordHash, &user.Status, &user.Origin,
		&user.MaxKeys, &user.Note, &user.AuthVersion, &user.CreatedAtMS, &user.UpdatedAtMS, &lastLogin); err != nil {
		return PortalSession{}, PortalUser{}, err
	}
	user.LastLoginAtMS = portalIntPtr(lastLogin)
	return session, user, nil
}

func (r *Repository) TouchPortalSession(ctx context.Context, tokenHash string, nowMS int64) error {
	db, err := r.portalDB()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE portal_sessions SET last_seen_at_ms = ? WHERE token_hash = ?`, nowMS, tokenHash)
	return err
}

func (r *Repository) DeletePortalSession(ctx context.Context, tokenHash string) error {
	db, err := r.portalDB()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `DELETE FROM portal_sessions WHERE token_hash = ?`, tokenHash)
	return err
}

// UpdatePortalPassword is the customer's own password change: it raises
// auth_version, ends every other session and keeps the current one valid by
// moving it to the new version.
func (r *Repository) UpdatePortalPassword(ctx context.Context, userID int64, passwordHash, keepTokenHash string, nowMS int64) error {
	db, err := r.portalDB()
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE portal_users SET password_hash = ?, auth_version = auth_version + 1, updated_at_ms = ? WHERE id = ?`, passwordHash, nowMS, userID); err != nil {
		return fmt.Errorf("update portal password: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM portal_sessions WHERE user_id = ? AND token_hash <> ?`, userID, keepTokenHash); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE portal_sessions SET auth_version = (SELECT auth_version FROM portal_users WHERE id = ?) WHERE token_hash = ?`, userID, keepTokenHash); err != nil {
		return err
	}
	return tx.Commit()
}

// Invites.

func (r *Repository) CreatePortalInvite(ctx context.Context, invite PortalInvite) (PortalInvite, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalInvite{}, err
	}
	result, err := db.ExecContext(ctx, `
		INSERT INTO portal_invites (code_hash, code_prefix, note, max_uses, expires_at_ms, created_at_ms)
		VALUES (?, ?, ?, ?, ?, ?)`, invite.CodeHash, invite.CodePrefix, invite.Note, invite.MaxUses,
		portalNullInt(invite.ExpiresAtMS), invite.CreatedAtMS)
	if err != nil {
		if isUniqueViolation(err) {
			return PortalInvite{}, ErrPortalConflict
		}
		return PortalInvite{}, fmt.Errorf("create portal invite: %w", err)
	}
	invite.ID, _ = result.LastInsertId()
	return invite, nil
}

func (r *Repository) ListPortalInvites(ctx context.Context) ([]PortalInvite, error) {
	db, err := r.portalDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `
		SELECT id, code_prefix, note, max_uses, used_count, expires_at_ms, revoked_at_ms, created_at_ms
		FROM portal_invites ORDER BY id DESC LIMIT 500`)
	if err != nil {
		return nil, fmt.Errorf("list portal invites: %w", err)
	}
	defer rows.Close()
	items := []PortalInvite{}
	for rows.Next() {
		var item PortalInvite
		var expires, revoked sql.NullInt64
		if err := rows.Scan(&item.ID, &item.CodePrefix, &item.Note, &item.MaxUses, &item.UsedCount, &expires, &revoked, &item.CreatedAtMS); err != nil {
			return nil, err
		}
		item.ExpiresAtMS = portalIntPtr(expires)
		item.RevokedAtMS = portalIntPtr(revoked)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (r *Repository) RevokePortalInvite(ctx context.Context, id, nowMS int64) error {
	db, err := r.portalDB()
	if err != nil {
		return err
	}
	result, err := db.ExecContext(ctx, `UPDATE portal_invites SET revoked_at_ms = COALESCE(revoked_at_ms, ?) WHERE id = ?`, nowMS, id)
	if err != nil {
		return err
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return ErrNotFound
	}
	return nil
}

// Keys.

const portalKeyColumns = `k.id, k.user_id, k.name, k.key_fingerprint, k.key_prefix, k.key_last4, k.status,
	k.sync_state, k.sync_error, k.synced_at_ms, k.expires_at_ms, k.request_count, k.last_used_at_ms,
	k.created_at_ms, k.revoked_at_ms, u.status`

func scanPortalKey(row portalScanner) (PortalKey, error) {
	var key PortalKey
	var synced, expires, lastUsed, revoked sql.NullInt64
	err := row.Scan(&key.ID, &key.UserID, &key.Name, &key.Fingerprint, &key.Prefix, &key.Last4, &key.Status,
		&key.SyncState, &key.SyncError, &synced, &expires, &key.RequestCount, &lastUsed, &key.CreatedAtMS,
		&revoked, &key.UserStatus)
	key.SyncedAtMS = portalIntPtr(synced)
	key.ExpiresAtMS = portalIntPtr(expires)
	key.LastUsedAtMS = portalIntPtr(lastUsed)
	key.RevokedAtMS = portalIntPtr(revoked)
	return key, err
}

func (r *Repository) queryPortalKeys(ctx context.Context, where string, args ...any) ([]PortalKey, error) {
	db, err := r.portalDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT `+portalKeyColumns+` FROM portal_api_keys k JOIN portal_users u ON u.id = k.user_id `+where, args...)
	if err != nil {
		return nil, fmt.Errorf("list portal keys: %w", err)
	}
	defer rows.Close()
	items := []PortalKey{}
	for rows.Next() {
		key, err := scanPortalKey(rows)
		if err != nil {
			return nil, fmt.Errorf("scan portal key: %w", err)
		}
		items = append(items, key)
	}
	return items, rows.Err()
}

// InsertPortalKey stores a new key in the pending sync state, enforcing the
// account's key limit in the same statement so two concurrent creations cannot
// both pass a separate count.
func (r *Repository) InsertPortalKey(ctx context.Context, key PortalKey) (PortalKey, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalKey{}, err
	}
	result, err := db.ExecContext(ctx, `
		INSERT INTO portal_api_keys (user_id, name, key_fingerprint, key_prefix, key_last4, status, sync_state,
			expires_at_ms, created_at_ms)
		SELECT ?, ?, ?, ?, ?, 'active', 'pending', ?, ?
		WHERE (SELECT COUNT(1) FROM portal_api_keys WHERE user_id = ? AND status = 'active')
		      < (SELECT max_keys FROM portal_users WHERE id = ?)`,
		key.UserID, key.Name, key.Fingerprint, key.Prefix, key.Last4, portalNullInt(key.ExpiresAtMS),
		key.CreatedAtMS, key.UserID, key.UserID)
	if err != nil {
		if isUniqueViolation(err) {
			return PortalKey{}, ErrPortalConflict
		}
		return PortalKey{}, fmt.Errorf("insert portal key: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return PortalKey{}, ErrPortalKeyLimit
	}
	id, _ := result.LastInsertId()
	return r.GetPortalKey(ctx, id)
}

// ErrPortalKeyLimit reports that the account already holds its maximum number
// of active keys.
var ErrPortalKeyLimit = errors.New("portal key limit reached")

func (r *Repository) GetPortalKey(ctx context.Context, id int64) (PortalKey, error) {
	items, err := r.queryPortalKeys(ctx, `WHERE k.id = ?`, id)
	if err != nil {
		return PortalKey{}, err
	}
	if len(items) == 0 {
		return PortalKey{}, ErrNotFound
	}
	return items[0], nil
}

// ListPortalKeys lists one account's keys, newest first. Revoked keys whose
// removal from CPA is confirmed are listed too: their history still names them.
func (r *Repository) ListPortalKeys(ctx context.Context, userID int64) ([]PortalKey, error) {
	return r.queryPortalKeys(ctx, `WHERE k.user_id = ? ORDER BY k.id DESC`, userID)
}

// ListPortalKeysForSync lists every key whose CPA state may still need a write:
// everything except revoked keys already confirmed removed.
func (r *Repository) ListPortalKeysForSync(ctx context.Context) ([]PortalKey, error) {
	return r.queryPortalKeys(ctx, `WHERE NOT (k.status = 'revoked' AND k.sync_state = 'removed') ORDER BY k.id ASC`)
}

// RevokePortalKey marks a key revoked. ownerID scopes a customer's own call;
// zero is the operator, who may revoke any key.
func (r *Repository) RevokePortalKey(ctx context.Context, id, ownerID, nowMS int64) (PortalKey, error) {
	db, err := r.portalDB()
	if err != nil {
		return PortalKey{}, err
	}
	query := `UPDATE portal_api_keys SET status = 'revoked', revoked_at_ms = COALESCE(revoked_at_ms, ?) WHERE id = ?`
	args := []any{nowMS, id}
	if ownerID > 0 {
		query += ` AND user_id = ?`
		args = append(args, ownerID)
	}
	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return PortalKey{}, fmt.Errorf("revoke portal key: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected == 0 {
		return PortalKey{}, ErrNotFound
	}
	return r.GetPortalKey(ctx, id)
}

// DeletePortalKey removes a key that never became usable (its CPA write failed
// at creation). A key that ever reached CPA is revoked instead, never deleted.
func (r *Repository) DeletePortalKey(ctx context.Context, id int64) error {
	db, err := r.portalDB()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `DELETE FROM portal_api_keys WHERE id = ? AND request_count = 0`, id)
	return err
}

func (r *Repository) SetPortalKeySync(ctx context.Context, id int64, state, syncError string, nowMS int64) error {
	db, err := r.portalDB()
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `UPDATE portal_api_keys SET sync_state = ?, sync_error = ?, synced_at_ms = ? WHERE id = ?`,
		state, truncateRunes(syncError, 512), nowMS, id)
	return err
}

// PortalKeyFingerprints maps every portal key's fingerprint to its id, so a
// reader of CPA's key list can tell which entries the portal owns.
func (r *Repository) PortalKeyFingerprints(ctx context.Context) (map[string]int64, error) {
	db, err := r.portalDB()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(ctx, `SELECT key_fingerprint, id FROM portal_api_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int64{}
	for rows.Next() {
		var fingerprint string
		var id int64
		if err := rows.Scan(&fingerprint, &id); err != nil {
			return nil, err
		}
		result[fingerprint] = id
	}
	return result, rows.Err()
}

func truncateRunes(value string, limit int) string {
	runes := []rune(strings.TrimSpace(value))
	if len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes)
}
