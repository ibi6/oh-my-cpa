package portal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/oh-my-cpa/oh-my-cpa/internal/config"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
)

// Errors the API maps to responses. They are codes, not prose.
var (
	ErrInvalidCredentials   = errors.New("invalid_credentials")
	ErrRegistrationClosed   = errors.New("registration_closed")
	ErrInviteRequired       = errors.New("invite_required")
	ErrInviteInvalid        = errors.New("invite_invalid")
	ErrUsernameTaken        = errors.New("username_taken")
	ErrKeyLimit             = errors.New("key_limit_reached")
	ErrGatewaySync          = errors.New("gateway_sync_failed")
	ErrNotFound             = errors.New("not_found")
	ErrSessionInvalid       = errors.New("session_invalid")
	ErrKeyStoreUnavailable  = errors.New("gateway_unavailable")
	ErrInvalidInviteRequest = errors.New("invalid_invite")
	ErrInvalidMaxKeys       = errors.New("invalid_max_keys")
	ErrInvalidStatus        = errors.New("invalid_status")
)

// KeyStore is CPA's client key list (access.api-keys) as the portal uses it.
//
// The portal only ever adds keys it generated and removes keys whose
// fingerprint it owns; it never rewrites an entry the operator added
// (AGENTS.md, zero-destructive adoption).
type KeyStore interface {
	// Fingerprints returns the usage fingerprint of every key CPA accepts.
	Fingerprints(ctx context.Context) (map[string]struct{}, error)
	// Add appends a key to CPA's list.
	Add(ctx context.Context, secret string) error
	// Remove deletes the key with this fingerprint; false means it was absent.
	Remove(ctx context.Context, fingerprint string) (bool, error)
}

// Fingerprinter derives the identity a key has in the request records.
type Fingerprinter interface {
	UsageClientKeyFingerprint(value string) (string, error)
}

// Service holds the portal's rules.
type Service struct {
	Repo   *repository.Repository
	Keys   KeyStore
	Config config.PortalConfig
	Logger *slog.Logger
	// Now overrides the clock in tests.
	Now func() time.Time
	// Alias, when set, names a key in the operator's caller-key list so the
	// console's own key page and request filters show whose key it is.
	Alias func(ctx context.Context, fingerprint, alias string)

	syncMu    sync.Mutex
	dummyOnce sync.Once
	dummy     string
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Service) dummyHash() string {
	s.dummyOnce.Do(func() { s.dummy = dummyHash() })
	return s.dummy
}

// NewUser describes an account to create.
type NewUser struct {
	Username    string
	Password    string
	DisplayName string
	Note        string
	MaxKeys     *int
	Origin      string
	InviteCode  string
}

const defaultMaxKeys = 10

func (s *Service) prepareUser(input NewUser) (repository.PortalUser, error) {
	username, err := NormalizeUsername(input.Username)
	if err != nil {
		return repository.PortalUser{}, err
	}
	if err := ValidatePassword(input.Password); err != nil {
		return repository.PortalUser{}, err
	}
	displayName, err := NormalizeDisplayName(input.DisplayName)
	if err != nil {
		return repository.PortalUser{}, err
	}
	note, err := NormalizeNote(input.Note)
	if err != nil {
		return repository.PortalUser{}, err
	}
	maxKeys := defaultMaxKeys
	if input.MaxKeys != nil {
		if *input.MaxKeys < 0 || *input.MaxKeys > 1000 {
			return repository.PortalUser{}, ErrInvalidMaxKeys
		}
		maxKeys = *input.MaxKeys
	}
	hash, err := HashPassword(input.Password)
	if err != nil {
		return repository.PortalUser{}, err
	}
	origin := input.Origin
	if origin == "" {
		origin = "admin"
	}
	return repository.PortalUser{
		Username: username, DisplayName: displayName, PasswordHash: hash,
		Status: repository.PortalUserActive, Origin: origin, MaxKeys: maxKeys, Note: note,
		CreatedAtMS: s.now().UnixMilli(),
	}, nil
}

// CreateUser is the operator creating an account.
func (s *Service) CreateUser(ctx context.Context, input NewUser) (repository.PortalUser, error) {
	input.Origin = "admin"
	user, err := s.prepareUser(input)
	if err != nil {
		return repository.PortalUser{}, err
	}
	created, err := s.Repo.CreatePortalUser(ctx, user)
	if errors.Is(err, repository.ErrPortalConflict) {
		return repository.PortalUser{}, ErrUsernameTaken
	}
	return created, err
}

// Register is a customer signing themselves up under the configured mode.
func (s *Service) Register(ctx context.Context, input NewUser) (repository.PortalUser, error) {
	switch s.Config.Registration {
	case config.PortalRegistrationOpen:
		input.Origin = "open"
		input.MaxKeys = nil
		user, err := s.prepareUser(input)
		if err != nil {
			return repository.PortalUser{}, err
		}
		created, err := s.Repo.CreatePortalUser(ctx, user)
		if errors.Is(err, repository.ErrPortalConflict) {
			return repository.PortalUser{}, ErrUsernameTaken
		}
		return created, err
	case config.PortalRegistrationInvite:
		code := strings.TrimSpace(input.InviteCode)
		if code == "" {
			return repository.PortalUser{}, ErrInviteRequired
		}
		input.Origin = "invite"
		input.MaxKeys = nil
		user, err := s.prepareUser(input)
		if err != nil {
			return repository.PortalUser{}, err
		}
		created, err := s.Repo.RegisterPortalUserWithInvite(ctx, user, HashToken(code), s.now().UnixMilli())
		switch {
		case errors.Is(err, repository.ErrPortalInviteInvalid):
			return repository.PortalUser{}, ErrInviteInvalid
		case errors.Is(err, repository.ErrPortalConflict):
			return repository.PortalUser{}, ErrUsernameTaken
		}
		return created, err
	default:
		return repository.PortalUser{}, ErrRegistrationClosed
	}
}

// Authenticate checks a username and password. A missing account, a wrong
// password and a disabled account are one answer, and all three cost one
// password derivation, so the response does not reveal which accounts exist.
func (s *Service) Authenticate(ctx context.Context, username, password string) (repository.PortalUser, error) {
	user, err := s.Repo.GetPortalUserByUsername(ctx, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			VerifyPassword(s.dummyHash(), password)
			return repository.PortalUser{}, ErrInvalidCredentials
		}
		return repository.PortalUser{}, err
	}
	if !VerifyPassword(user.PasswordHash, password) || user.Status != repository.PortalUserActive {
		return repository.PortalUser{}, ErrInvalidCredentials
	}
	_ = s.Repo.RecordPortalLogin(ctx, user.ID, s.now().UnixMilli())
	return user, nil
}

// IssueSession stores a new session and returns the cookie token.
func (s *Service) IssueSession(ctx context.Context, user repository.PortalUser, clientIP, userAgent string) (string, time.Time, error) {
	token, err := NewSessionToken()
	if err != nil {
		return "", time.Time{}, err
	}
	ttl := s.Config.SessionTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	now := s.now()
	expires := now.Add(ttl)
	if err := s.Repo.CreatePortalSession(ctx, repository.PortalSession{
		TokenHash: HashToken(token), UserID: user.ID, AuthVersion: user.AuthVersion, ExpiresAtMS: expires.UnixMilli(),
	}, clientIP, userAgent, now.UnixMilli()); err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

// ResolveSession returns the account behind a cookie token.
func (s *Service) ResolveSession(ctx context.Context, token string) (repository.PortalUser, string, error) {
	if strings.TrimSpace(token) == "" {
		return repository.PortalUser{}, "", ErrSessionInvalid
	}
	tokenHash := HashToken(token)
	now := s.now().UnixMilli()
	session, user, err := s.Repo.PortalSessionUser(ctx, tokenHash, now)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return repository.PortalUser{}, "", ErrSessionInvalid
		}
		return repository.PortalUser{}, "", err
	}
	// A write per request would contend for the single SQLite connection; once a
	// minute is enough for "last seen".
	if now-session.LastSeenMS > time.Minute.Milliseconds() {
		_ = s.Repo.TouchPortalSession(ctx, tokenHash, now)
	}
	return user, tokenHash, nil
}

// EndSession deletes the session behind a cookie token.
func (s *Service) EndSession(ctx context.Context, token string) error {
	if strings.TrimSpace(token) == "" {
		return nil
	}
	return s.Repo.DeletePortalSession(ctx, HashToken(token))
}

// ChangePassword is the customer's own change: it requires the current password.
func (s *Service) ChangePassword(ctx context.Context, user repository.PortalUser, sessionHash, current, next string) error {
	fresh, err := s.Repo.GetPortalUser(ctx, user.ID)
	if err != nil {
		return err
	}
	if !VerifyPassword(fresh.PasswordHash, current) {
		return ErrInvalidCredentials
	}
	if err := ValidatePassword(next); err != nil {
		return err
	}
	hash, err := HashPassword(next)
	if err != nil {
		return err
	}
	return s.Repo.UpdatePortalPassword(ctx, user.ID, hash, sessionHash, s.now().UnixMilli())
}

// UserPatch is an operator update.
type UserPatch struct {
	DisplayName *string
	Status      *string
	Note        *string
	MaxKeys     *int
	Password    *string
}

// UpdateUser applies an operator update and, when the account's access
// changed, reconciles its keys with CPA straight away.
func (s *Service) UpdateUser(ctx context.Context, id int64, input UserPatch) (repository.PortalUser, error) {
	patch := repository.PortalUserPatch{MaxKeys: input.MaxKeys}
	if input.DisplayName != nil {
		value, err := NormalizeDisplayName(*input.DisplayName)
		if err != nil {
			return repository.PortalUser{}, err
		}
		patch.DisplayName = &value
	}
	if input.Note != nil {
		value, err := NormalizeNote(*input.Note)
		if err != nil {
			return repository.PortalUser{}, err
		}
		patch.Note = &value
	}
	if input.Status != nil {
		if *input.Status != repository.PortalUserActive && *input.Status != repository.PortalUserDisabled {
			return repository.PortalUser{}, ErrInvalidStatus
		}
		patch.Status = input.Status
	}
	if input.MaxKeys != nil && (*input.MaxKeys < 0 || *input.MaxKeys > 1000) {
		return repository.PortalUser{}, ErrInvalidMaxKeys
	}
	if input.Password != nil {
		if err := ValidatePassword(*input.Password); err != nil {
			return repository.PortalUser{}, err
		}
		hash, err := HashPassword(*input.Password)
		if err != nil {
			return repository.PortalUser{}, err
		}
		patch.PasswordHash = &hash
	}
	user, err := s.Repo.UpdatePortalUser(ctx, id, patch, s.now().UnixMilli())
	if errors.Is(err, sql.ErrNoRows) {
		return repository.PortalUser{}, ErrNotFound
	}
	if err != nil {
		return repository.PortalUser{}, err
	}
	if input.Status != nil && s.Config.Enabled && s.Keys != nil {
		if _, syncErr := s.Reconcile(ctx); syncErr != nil {
			s.logger().Warn("portal key reconcile after account change failed", "user_id", id, "error", syncErr.Error())
		}
	}
	return user, nil
}

// CreatedKey is a new key and the plaintext shown exactly once.
type CreatedKey struct {
	Key    repository.PortalKey
	Secret string
}

// CreateKey issues a key for an account and adds it to CPA. If CPA refuses
// the write the key is deleted again: a key the gateway never accepted must not
// be handed out.
func (s *Service) CreateKey(ctx context.Context, user repository.PortalUser, name string, expiresAtMS *int64) (CreatedKey, error) {
	if !s.Config.Enabled || s.Keys == nil {
		return CreatedKey{}, ErrKeyStoreUnavailable
	}
	keyName, err := NormalizeKeyName(name)
	if err != nil {
		return CreatedKey{}, err
	}
	now := s.now()
	if expiresAtMS != nil {
		limit := now.AddDate(10, 0, 0).UnixMilli()
		if *expiresAtMS <= now.UnixMilli() || *expiresAtMS > limit {
			return CreatedKey{}, ErrInvalidExpiry
		}
	}
	secret, err := NewKeySecret()
	if err != nil {
		return CreatedKey{}, err
	}
	fingerprint, err := s.Repo.UsageClientKeyFingerprint(secret)
	if err != nil {
		return CreatedKey{}, err
	}
	prefix, last4 := KeyDisplayParts(secret)

	// The reconciler must not judge this key between its insert and its CPA
	// write, or it would record the brief absence as "missing".
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	key, err := s.Repo.InsertPortalKey(ctx, repository.PortalKey{
		UserID: user.ID, Name: keyName, Fingerprint: fingerprint, Prefix: prefix, Last4: last4,
		ExpiresAtMS: expiresAtMS, CreatedAtMS: now.UnixMilli(),
	})
	if errors.Is(err, repository.ErrPortalKeyLimit) {
		return CreatedKey{}, ErrKeyLimit
	}
	if err != nil {
		return CreatedKey{}, err
	}
	if addErr := s.Keys.Add(ctx, secret); addErr != nil {
		if deleteErr := s.Repo.DeletePortalKey(context.WithoutCancel(ctx), key.ID); deleteErr != nil {
			s.logger().Error("could not discard a portal key CPA refused", "key_id", key.ID, "error", deleteErr.Error())
		}
		return CreatedKey{}, fmt.Errorf("%w: %w", ErrGatewaySync, addErr)
	}
	nowMS := s.now().UnixMilli()
	if err := s.Repo.SetPortalKeySync(ctx, key.ID, repository.PortalSyncSynced, "", nowMS); err != nil {
		s.logger().Warn("could not record a portal key's sync state", "key_id", key.ID, "error", err.Error())
	}
	key.SyncState = repository.PortalSyncSynced
	key.SyncedAtMS = &nowMS
	if s.Alias != nil {
		s.Alias(ctx, fingerprint, aliasFor(user.Username, keyName))
	}
	return CreatedKey{Key: key, Secret: secret}, nil
}

func aliasFor(username, keyName string) string {
	alias := "portal:" + username + "/" + keyName
	runes := []rune(alias)
	if len(runes) > 64 {
		runes = runes[:64]
	}
	return string(runes)
}

// RevokeKey revokes a key and removes it from CPA. ownerID scopes a customer's
// own call; zero is the operator. The revocation stands even when CPA cannot be
// reached: the key is marked failed and the reconciler retries the removal.
func (s *Service) RevokeKey(ctx context.Context, keyID, ownerID int64) (repository.PortalKey, error) {
	key, err := s.Repo.RevokePortalKey(ctx, keyID, ownerID, s.now().UnixMilli())
	if errors.Is(err, repository.ErrNotFound) || errors.Is(err, sql.ErrNoRows) {
		return repository.PortalKey{}, ErrNotFound
	}
	if err != nil {
		return repository.PortalKey{}, err
	}
	if s.Keys == nil || !s.Config.Enabled {
		return key, nil
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	state, syncErr := s.removeFromCPA(ctx, key)
	key.SyncState = state
	if syncErr != nil {
		key.SyncError = syncErr.Error()
	}
	return key, nil
}

func (s *Service) removeFromCPA(ctx context.Context, key repository.PortalKey) (string, error) {
	_, err := s.Keys.Remove(ctx, key.Fingerprint)
	nowMS := s.now().UnixMilli()
	if err != nil {
		_ = s.Repo.SetPortalKeySync(ctx, key.ID, repository.PortalSyncFailed, err.Error(), nowMS)
		return repository.PortalSyncFailed, err
	}
	_ = s.Repo.SetPortalKeySync(ctx, key.ID, repository.PortalSyncRemoved, "", nowMS)
	return repository.PortalSyncRemoved, nil
}

// SyncReport is what one reconciliation pass did.
type SyncReport struct {
	Checked int `json:"checked"`
	Synced  int `json:"synced"`
	Removed int `json:"removed"`
	Missing int `json:"missing"`
	Failed  int `json:"failed"`
}

// Reconcile compares every portal key with CPA's list and converges what it
// can: unwanted keys (revoked, expired, account disabled) are removed, wanted
// keys present in CPA are marked synced, and wanted keys absent from CPA are
// marked missing. A missing key cannot be re-added, because the plaintext is
// not kept; the customer issues a new one.
func (s *Service) Reconcile(ctx context.Context) (SyncReport, error) {
	var report SyncReport
	if !s.Config.Enabled || s.Keys == nil {
		return report, nil
	}
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	keys, err := s.Repo.ListPortalKeysForSync(ctx)
	if err != nil {
		return report, err
	}
	if len(keys) == 0 {
		return report, nil
	}
	present, err := s.Keys.Fingerprints(ctx)
	if err != nil {
		return report, fmt.Errorf("%w: %w", ErrKeyStoreUnavailable, err)
	}
	now := s.now().UnixMilli()
	for _, key := range keys {
		report.Checked++
		_, inCPA := present[key.Fingerprint]
		wanted := key.Wanted(now)
		switch {
		case wanted && inCPA:
			report.Synced++
			if key.SyncState != repository.PortalSyncSynced {
				_ = s.Repo.SetPortalKeySync(ctx, key.ID, repository.PortalSyncSynced, "", now)
			}
		case wanted && !inCPA:
			report.Missing++
			if key.SyncState != repository.PortalSyncMissing {
				_ = s.Repo.SetPortalKeySync(ctx, key.ID, repository.PortalSyncMissing, "not present in CPA access.api-keys", now)
			}
		case !wanted && inCPA:
			if state, _ := s.removeFromCPA(ctx, key); state == repository.PortalSyncFailed {
				report.Failed++
			} else {
				report.Removed++
			}
		default:
			if key.SyncState != repository.PortalSyncRemoved {
				_ = s.Repo.SetPortalKeySync(ctx, key.ID, repository.PortalSyncRemoved, "", now)
				report.Removed++
			}
		}
	}
	return report, nil
}

// Run reconciles on the configured interval until ctx ends.
func (s *Service) Run(ctx context.Context) error {
	if !s.Config.Enabled || s.Keys == nil {
		return nil
	}
	interval := s.Config.SyncInterval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := s.Reconcile(ctx); err != nil && !errors.Is(err, context.Canceled) {
			s.logger().Warn("portal key reconcile failed", "error", err.Error())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// NewInvite is an invite to create.
type NewInvite struct {
	MaxUses     int
	ExpiresAtMS *int64
	Note        string
}

// CreateInvite issues an invite code, returned once.
func (s *Service) CreateInvite(ctx context.Context, input NewInvite) (repository.PortalInvite, string, error) {
	if input.MaxUses == 0 {
		input.MaxUses = 1
	}
	if input.MaxUses < 1 || input.MaxUses > 10000 {
		return repository.PortalInvite{}, "", ErrInvalidInviteRequest
	}
	now := s.now()
	if input.ExpiresAtMS != nil && *input.ExpiresAtMS <= now.UnixMilli() {
		return repository.PortalInvite{}, "", ErrInvalidExpiry
	}
	note, err := NormalizeNote(input.Note)
	if err != nil {
		return repository.PortalInvite{}, "", err
	}
	code, err := NewInviteCode()
	if err != nil {
		return repository.PortalInvite{}, "", err
	}
	invite, err := s.Repo.CreatePortalInvite(ctx, repository.PortalInvite{
		CodeHash: HashToken(code), CodePrefix: code[:12], Note: note, MaxUses: input.MaxUses,
		ExpiresAtMS: input.ExpiresAtMS, CreatedAtMS: now.UnixMilli(),
	})
	return invite, code, err
}
