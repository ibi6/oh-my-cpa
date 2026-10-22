package portal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oh-my-cpa/oh-my-cpa/internal/config"
	"github.com/oh-my-cpa/oh-my-cpa/internal/crypto"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
)

func init() {
	// The production work factor makes every test that hashes take seconds.
	PasswordIterations = 1000
}

var dsnCounter atomic.Int64

// fakeKeys stands in for CPA's access.api-keys.
type fakeKeys struct {
	mu      sync.Mutex
	repo    *repository.Repository
	present map[string]struct{}
	addErr  error
	rmErr   error
	listErr error
}

func (f *fakeKeys) Fingerprints(context.Context) (map[string]struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	copied := make(map[string]struct{}, len(f.present))
	for key := range f.present {
		copied[key] = struct{}{}
	}
	return copied, nil
}

func (f *fakeKeys) Add(_ context.Context, secret string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return f.addErr
	}
	fingerprint, err := f.repo.UsageClientKeyFingerprint(secret)
	if err != nil {
		return err
	}
	f.present[fingerprint] = struct{}{}
	return nil
}

func (f *fakeKeys) Remove(_ context.Context, fingerprint string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rmErr != nil {
		return false, f.rmErr
	}
	_, ok := f.present[fingerprint]
	delete(f.present, fingerprint)
	return ok, nil
}

func (f *fakeKeys) has(fingerprint string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.present[fingerprint]
	return ok
}

func newTestService(t *testing.T, registration string) (*Service, *fakeKeys) {
	t.Helper()
	cipher, err := crypto.New("01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	db, err := repository.Open(context.Background(), fmt.Sprintf("file:portalsvc_%d?mode=memory&cache=shared", dsnCounter.Add(1)), repository.WithCipher(cipher))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := repository.New(db)
	keys := &fakeKeys{repo: repo, present: map[string]struct{}{}}
	return &Service{
		Repo: repo, Keys: keys,
		Config: config.PortalConfig{Enabled: true, Registration: registration, SessionTTL: time.Hour, SyncInterval: time.Minute},
	}, keys
}

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "pbkdf2-sha256$") || strings.Contains(hash, "correct horse") {
		t.Fatalf("hash = %q", hash)
	}
	if !VerifyPassword(hash, "correct horse") || VerifyPassword(hash, "wrong horse") {
		t.Fatal("password verification is wrong")
	}
	for _, malformed := range []string{"", "plain", "pbkdf2-sha256$x$y$z", "md5$1$a$b"} {
		if VerifyPassword(malformed, "correct horse") {
			t.Fatalf("malformed hash %q verified", malformed)
		}
	}
	again, _ := HashPassword("correct horse")
	if again == hash {
		t.Fatal("two hashes of one password are identical: the salt is not random")
	}
}

func TestSecretsHaveTheirShapes(t *testing.T) {
	secret, err := NewKeySecret()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, KeyPrefix) || len(secret) != len(KeyPrefix)+40 {
		t.Fatalf("key = %q", secret)
	}
	prefix, last4 := KeyDisplayParts(secret)
	if prefix != secret[:len(KeyPrefix)+4] || last4 != secret[len(secret)-4:] {
		t.Fatalf("display parts = %q %q", prefix, last4)
	}
	code, _ := NewInviteCode()
	if !strings.HasPrefix(code, "omc-inv-") {
		t.Fatalf("invite = %q", code)
	}
	if HashToken("a") == HashToken("b") || len(HashToken("a")) != 64 {
		t.Fatal("token hash is wrong")
	}
}

func TestValidation(t *testing.T) {
	for _, bad := range []string{"", "ab", "-abc", "has space", strings.Repeat("a", 33), "名字abc"} {
		if _, err := NormalizeUsername(bad); !errors.Is(err, ErrInvalidUsername) {
			t.Errorf("username %q accepted", bad)
		}
	}
	if name, err := NormalizeUsername("  Alice_01 "); err != nil || name != "Alice_01" {
		t.Errorf("username = %q, %v", name, err)
	}
	if ValidatePassword("short") == nil || ValidatePassword(strings.Repeat("x", 129)) == nil {
		t.Error("password length not enforced")
	}
	if _, err := NormalizeKeyName("bad\u202ename"); err == nil {
		t.Error("bidi override accepted in a key name")
	}
	if _, err := NormalizeKeyName(""); err == nil {
		t.Error("empty key name accepted")
	}
	if _, err := NormalizeDisplayName("line\nbreak"); err == nil {
		t.Error("control character accepted in a display name")
	}
}

func TestRegistrationModes(t *testing.T) {
	ctx := context.Background()
	closed, _ := newTestService(t, config.PortalRegistrationOff)
	if _, err := closed.Register(ctx, NewUser{Username: "someone", Password: "password1"}); !errors.Is(err, ErrRegistrationClosed) {
		t.Fatalf("closed registration = %v", err)
	}

	open, _ := newTestService(t, config.PortalRegistrationOpen)
	user, err := open.Register(ctx, NewUser{Username: "someone", Password: "password1", MaxKeys: intPtr(999)})
	if err != nil {
		t.Fatal(err)
	}
	if user.Origin != "open" || user.MaxKeys != defaultMaxKeys {
		t.Fatalf("self-registered account = %+v (a customer must not pick their own limit)", user)
	}
	if _, err := open.Register(ctx, NewUser{Username: "SOMEONE", Password: "password1"}); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("duplicate = %v", err)
	}

	invite, _ := newTestService(t, config.PortalRegistrationInvite)
	if _, err := invite.Register(ctx, NewUser{Username: "someone", Password: "password1"}); !errors.Is(err, ErrInviteRequired) {
		t.Fatalf("no invite = %v", err)
	}
	if _, err := invite.Register(ctx, NewUser{Username: "someone", Password: "password1", InviteCode: "omc-inv-bogus"}); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("bogus invite = %v", err)
	}
	_, code, err := invite.CreateInvite(ctx, NewInvite{MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := invite.Register(ctx, NewUser{Username: "someone", Password: "password1", InviteCode: code}); err != nil {
		t.Fatal(err)
	}
	if _, err := invite.Register(ctx, NewUser{Username: "another", Password: "password1", InviteCode: code}); !errors.Is(err, ErrInviteInvalid) {
		t.Fatalf("spent invite = %v", err)
	}
}

func intPtr(v int) *int { return &v }

func TestAuthenticateAndSessions(t *testing.T) {
	ctx := context.Background()
	service, _ := newTestService(t, config.PortalRegistrationOff)
	user, err := service.CreateUser(ctx, NewUser{Username: "carol", Password: "password1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, "carol", "wrong-password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}
	if _, err := service.Authenticate(ctx, "nobody", "password1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user = %v", err)
	}
	signedIn, err := service.Authenticate(ctx, "Carol", "password1")
	if err != nil || signedIn.ID != user.ID {
		t.Fatalf("sign-in = %+v, %v", signedIn, err)
	}
	token, _, err := service.IssueSession(ctx, signedIn, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	resolved, sessionHash, err := service.ResolveSession(ctx, token)
	if err != nil || resolved.ID != user.ID {
		t.Fatalf("session = %+v, %v", resolved, err)
	}
	if err := service.ChangePassword(ctx, resolved, sessionHash, "wrong", "password2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("change with wrong current password = %v", err)
	}
	if err := service.ChangePassword(ctx, resolved, sessionHash, "password1", "password2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ResolveSession(ctx, token); err != nil {
		t.Fatalf("the changing session ended: %v", err)
	}
	disabled := repository.PortalUserDisabled
	if _, err := service.UpdateUser(ctx, user.ID, UserPatch{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.ResolveSession(ctx, token); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("disabled account's session = %v", err)
	}
	if _, err := service.Authenticate(ctx, "carol", "password2"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled sign-in = %v", err)
	}
	if err := service.EndSession(ctx, token); err != nil {
		t.Fatal(err)
	}
}

func TestKeyLifecycleSyncsWithCPA(t *testing.T) {
	ctx := context.Background()
	service, keys := newTestService(t, config.PortalRegistrationOff)
	user, err := service.CreateUser(ctx, NewUser{Username: "dave", Password: "password1", MaxKeys: intPtr(2)})
	if err != nil {
		t.Fatal(err)
	}
	var aliased []string
	service.Alias = func(_ context.Context, _ string, alias string) { aliased = append(aliased, alias) }

	created, err := service.CreateKey(ctx, user, "laptop", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Secret, KeyPrefix) || created.Key.SyncState != repository.PortalSyncSynced {
		t.Fatalf("created = %+v", created.Key)
	}
	fingerprint, _ := service.Repo.UsageClientKeyFingerprint(created.Secret)
	if !keys.has(fingerprint) {
		t.Fatal("the new key was not added to CPA")
	}
	if len(aliased) != 1 || aliased[0] != "portal:dave/laptop" {
		t.Fatalf("aliases = %v", aliased)
	}
	stored, _ := service.Repo.GetPortalKey(ctx, created.Key.ID)
	if stored.Fingerprint != fingerprint || strings.Contains(stored.Prefix+stored.Last4, created.Secret) {
		t.Fatalf("stored key = %+v", stored)
	}

	// CPA refusing the write leaves no key behind.
	keys.addErr = errors.New("gateway down")
	if _, err := service.CreateKey(ctx, user, "phone", nil); !errors.Is(err, ErrGatewaySync) {
		t.Fatalf("refused create = %v", err)
	}
	keys.addErr = nil
	list, _ := service.Repo.ListPortalKeys(ctx, user.ID)
	if len(list) != 1 {
		t.Fatalf("a refused key was kept: %d keys", len(list))
	}

	past := time.Now().Add(-time.Hour).UnixMilli()
	if _, err := service.CreateKey(ctx, user, "old", &past); !errors.Is(err, ErrInvalidExpiry) {
		t.Fatalf("past expiry = %v", err)
	}
	if _, err := service.CreateKey(ctx, user, "second", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := service.CreateKey(ctx, user, "third", nil); !errors.Is(err, ErrKeyLimit) {
		t.Fatalf("over limit = %v", err)
	}

	other, _ := service.CreateUser(ctx, NewUser{Username: "eve", Password: "password1"})
	if _, err := service.RevokeKey(ctx, created.Key.ID, other.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign revoke = %v", err)
	}
	revoked, err := service.RevokeKey(ctx, created.Key.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != repository.PortalKeyRevoked || revoked.SyncState != repository.PortalSyncRemoved || keys.has(fingerprint) {
		t.Fatalf("revoked = %+v, still in CPA = %v", revoked, keys.has(fingerprint))
	}
}

func TestReconcileConverges(t *testing.T) {
	ctx := context.Background()
	service, keys := newTestService(t, config.PortalRegistrationOff)
	user, _ := service.CreateUser(ctx, NewUser{Username: "frank", Password: "password1"})
	first, err := service.CreateKey(ctx, user, "first", nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateKey(ctx, user, "second", nil)
	if err != nil {
		t.Fatal(err)
	}
	firstFP, _ := service.Repo.UsageClientKeyFingerprint(first.Secret)
	secondFP, _ := service.Repo.UsageClientKeyFingerprint(second.Secret)

	// Someone removed the first key from CPA by hand.
	_, _ = keys.Remove(ctx, firstFP)
	report, err := service.Reconcile(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if report.Missing != 1 || report.Synced != 1 {
		t.Fatalf("report = %+v", report)
	}
	stored, _ := service.Repo.GetPortalKey(ctx, first.Key.ID)
	if stored.SyncState != repository.PortalSyncMissing {
		t.Fatalf("missing key state = %q", stored.SyncState)
	}

	// Disabling the account removes its keys from CPA.
	disabled := repository.PortalUserDisabled
	if _, err := service.UpdateUser(ctx, user.ID, UserPatch{Status: &disabled}); err != nil {
		t.Fatal(err)
	}
	if keys.has(secondFP) {
		t.Fatal("a disabled account's key is still in CPA")
	}

	// A removal CPA refused is retried by the next pass.
	active := repository.PortalUserActive
	if _, err := service.UpdateUser(ctx, user.ID, UserPatch{Status: &active}); err != nil {
		t.Fatal(err)
	}
	third, err := service.CreateKey(ctx, user, "third", nil)
	if err != nil {
		t.Fatal(err)
	}
	thirdFP, _ := service.Repo.UsageClientKeyFingerprint(third.Secret)
	keys.rmErr = errors.New("gateway busy")
	if _, err := service.RevokeKey(ctx, third.Key.ID, 0); err != nil {
		t.Fatalf("a revocation must stand when CPA is unreachable: %v", err)
	}
	if stored, _ := service.Repo.GetPortalKey(ctx, third.Key.ID); stored.SyncState != repository.PortalSyncFailed {
		t.Fatalf("unreachable removal state = %q", stored.SyncState)
	}
	keys.rmErr = nil
	if _, err := service.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if keys.has(thirdFP) {
		t.Fatal("the reconciler did not retry the removal")
	}

	// An unreachable CPA is an error, not a mass "missing".
	keys.listErr = errors.New("down")
	if _, err := service.Reconcile(ctx); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Fatalf("unreachable list = %v", err)
	}
}

func TestDisabledPortalIssuesNoKeys(t *testing.T) {
	ctx := context.Background()
	service, _ := newTestService(t, config.PortalRegistrationOff)
	user, _ := service.CreateUser(ctx, NewUser{Username: "grace", Password: "password1"})
	service.Config.Enabled = false
	if _, err := service.CreateKey(ctx, user, "k", nil); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Fatalf("disabled create = %v", err)
	}
	if report, err := service.Reconcile(ctx); err != nil || report.Checked != 0 {
		t.Fatalf("disabled reconcile = %+v, %v", report, err)
	}
}
