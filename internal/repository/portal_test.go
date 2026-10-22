package repository

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oh-my-cpa/oh-my-cpa/internal/crypto"
	"github.com/oh-my-cpa/oh-my-cpa/internal/domain"
	"github.com/oh-my-cpa/oh-my-cpa/internal/usage"
)

var portalTestDSN atomic.Int64

func portalTestRepository(t *testing.T) *Repository {
	t.Helper()
	cipher, err := crypto.New("01234567890123456789012345678901")
	if err != nil {
		t.Fatal(err)
	}
	dsn := fmt.Sprintf("file:portal_%d?mode=memory&cache=shared", portalTestDSN.Add(1))
	db, err := Open(context.Background(), dsn, WithCipher(cipher))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return New(db)
}

func portalTestUser(t *testing.T, repo *Repository, username string, maxKeys int) PortalUser {
	t.Helper()
	user, err := repo.CreatePortalUser(context.Background(), PortalUser{
		Username: username, PasswordHash: "x", Status: PortalUserActive, Origin: "admin", MaxKeys: maxKeys,
	})
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func portalTestKey(t *testing.T, repo *Repository, user PortalUser, secret, name string) PortalKey {
	t.Helper()
	fingerprint, err := repo.UsageClientKeyFingerprint(secret)
	if err != nil {
		t.Fatal(err)
	}
	key, err := repo.InsertPortalKey(context.Background(), PortalKey{
		UserID: user.ID, Name: name, Fingerprint: fingerprint, Prefix: secret[:11], Last4: secret[len(secret)-4:],
		CreatedAtMS: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestPortalUsernamesAreUniqueIgnoringCase(t *testing.T) {
	repo := portalTestRepository(t)
	portalTestUser(t, repo, "Alice", 10)
	_, err := repo.CreatePortalUser(context.Background(), PortalUser{
		Username: "alice", PasswordHash: "x", Status: PortalUserActive, Origin: "admin", MaxKeys: 10,
	})
	if !errors.Is(err, ErrPortalConflict) {
		t.Fatalf("duplicate username error = %v, want conflict", err)
	}
	found, err := repo.GetPortalUserByUsername(context.Background(), "ALICE")
	if err != nil || found.Username != "Alice" {
		t.Fatalf("lookup by username ignoring case = %+v, %v", found, err)
	}
}

func TestPortalInviteIsSpentAtomicallyWithTheAccount(t *testing.T) {
	repo := portalTestRepository(t)
	ctx := context.Background()
	now := time.Now().UnixMilli()
	if _, err := repo.CreatePortalInvite(ctx, PortalInvite{CodeHash: "h1", CodePrefix: "omc-inv-abcd", MaxUses: 1, CreatedAtMS: now}); err != nil {
		t.Fatal(err)
	}
	first := PortalUser{Username: "first", PasswordHash: "x", Status: PortalUserActive, Origin: "invite", MaxKeys: 3}
	if _, err := repo.RegisterPortalUserWithInvite(ctx, first, "h1", now); err != nil {
		t.Fatal(err)
	}
	second := PortalUser{Username: "second", PasswordHash: "x", Status: PortalUserActive, Origin: "invite", MaxKeys: 3}
	if _, err := repo.RegisterPortalUserWithInvite(ctx, second, "h1", now); !errors.Is(err, ErrPortalInviteInvalid) {
		t.Fatalf("second redemption error = %v, want invalid invite", err)
	}
	if _, err := repo.GetPortalUserByUsername(ctx, "second"); err == nil {
		t.Fatal("an account was created on a spent invite")
	}
	// A taken username must not spend a use either.
	if _, err := repo.CreatePortalInvite(ctx, PortalInvite{CodeHash: "h2", CodePrefix: "omc-inv-efgh", MaxUses: 1, CreatedAtMS: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RegisterPortalUserWithInvite(ctx, first, "h2", now); !errors.Is(err, ErrPortalConflict) {
		t.Fatalf("duplicate registration error = %v, want conflict", err)
	}
	invites, err := repo.ListPortalInvites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, invite := range invites {
		if invite.CodeHash == "h2" && invite.UsedCount != 0 {
			t.Fatalf("a failed registration spent an invite use: %+v", invite)
		}
	}
}

func TestPortalKeyLimitIsEnforcedOnInsert(t *testing.T) {
	repo := portalTestRepository(t)
	user := portalTestUser(t, repo, "limited", 1)
	key := portalTestKey(t, repo, user, "sk-omc-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "one")
	if key.SyncState != PortalSyncPending || key.Status != PortalKeyActive {
		t.Fatalf("new key = %+v", key)
	}
	fingerprint, _ := repo.UsageClientKeyFingerprint("sk-omc-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	_, err := repo.InsertPortalKey(context.Background(), PortalKey{UserID: user.ID, Name: "two", Fingerprint: fingerprint, Prefix: "sk-omc-bbbb", Last4: "bbbb"})
	if !errors.Is(err, ErrPortalKeyLimit) {
		t.Fatalf("second key error = %v, want limit", err)
	}
	// A revoked key frees its slot.
	if _, err := repo.RevokePortalKey(context.Background(), key.ID, user.ID, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.InsertPortalKey(context.Background(), PortalKey{UserID: user.ID, Name: "two", Fingerprint: fingerprint, Prefix: "sk-omc-bbbb", Last4: "bbbb"}); err != nil {
		t.Fatalf("key after revocation: %v", err)
	}
}

func TestPortalRevokeIsScopedToTheOwner(t *testing.T) {
	repo := portalTestRepository(t)
	owner := portalTestUser(t, repo, "owner", 5)
	other := portalTestUser(t, repo, "other", 5)
	key := portalTestKey(t, repo, owner, "sk-omc-cccccccccccccccccccccccccccccccccccccccc", "mine")
	if _, err := repo.RevokePortalKey(context.Background(), key.ID, other.ID, time.Now().UnixMilli()); err == nil {
		t.Fatal("another account revoked a key it does not own")
	}
	stored, err := repo.GetPortalKey(context.Background(), key.ID)
	if err != nil || stored.Status != PortalKeyActive {
		t.Fatalf("key after foreign revoke = %+v, %v", stored, err)
	}
}

func TestPortalSessionEndsWhenTheAccountIsDisabledOrRepassworded(t *testing.T) {
	repo := portalTestRepository(t)
	ctx := context.Background()
	user := portalTestUser(t, repo, "sessions", 5)
	now := time.Now().UnixMilli()
	session := PortalSession{TokenHash: "t1", UserID: user.ID, AuthVersion: user.AuthVersion, ExpiresAtMS: now + 60_000}
	if err := repo.CreatePortalSession(ctx, session, "127.0.0.1", "test", now); err != nil {
		t.Fatal(err)
	}
	if _, resolved, err := repo.PortalSessionUser(ctx, "t1", now); err != nil || resolved.ID != user.ID {
		t.Fatalf("live session = %+v, %v", resolved, err)
	}
	if _, _, err := repo.PortalSessionUser(ctx, "t1", now+120_000); err == nil {
		t.Fatal("an expired session resolved")
	}
	disabled := PortalUserDisabled
	if _, err := repo.UpdatePortalUser(ctx, user.ID, PortalUserPatch{Status: &disabled}, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.PortalSessionUser(ctx, "t1", now); err == nil {
		t.Fatal("a disabled account's session still resolves")
	}

	active := PortalUserActive
	user, err := repo.UpdatePortalUser(ctx, user.ID, PortalUserPatch{Status: &active}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, hash := range []string{"keep", "drop"} {
		if err := repo.CreatePortalSession(ctx, PortalSession{TokenHash: hash, UserID: user.ID, AuthVersion: user.AuthVersion, ExpiresAtMS: now + 60_000}, "", "", now); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.UpdatePortalPassword(ctx, user.ID, "y", "keep", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.PortalSessionUser(ctx, "keep", now); err != nil {
		t.Fatalf("the session that changed the password ended: %v", err)
	}
	if _, _, err := repo.PortalSessionUser(ctx, "drop", now); err == nil {
		t.Fatal("another session survived a password change")
	}
}

func TestPortalUsageIsAttributedOnIngest(t *testing.T) {
	repo := portalTestRepository(t)
	ctx := context.Background()
	alice := portalTestUser(t, repo, "alice", 5)
	bob := portalTestUser(t, repo, "bob", 5)
	aliceSecret := "sk-omc-dddddddddddddddddddddddddddddddddddddddd"
	aliceKey := portalTestKey(t, repo, alice, aliceSecret, "laptop")
	portalTestKey(t, repo, bob, "sk-omc-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "server")

	nowTime := time.Now().UTC()
	if err := repo.UpsertInstance(ctx, domain.CPAInstance{
		ID: "default", Name: "Default", BaseURL: "http://cpa:8317", CreatedAt: nowTime, UpdatedAt: nowTime,
		ManagementKeyCiphertext: []byte("c"), ManagementKeyNonce: []byte("n"),
	}); err != nil {
		t.Fatal(err)
	}
	day := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	event := func(id, key, model string, at time.Time, failed bool, total int64) usage.Event {
		return usage.Event{
			InstanceID: "default", EventKey: id, RequestID: id, APIGroupKey: key, Model: model,
			AuthIndex: "auth-1", AuthType: "oauth", Provider: "gemini", TimestampMS: at.UnixMilli(),
			Failed: failed, Generate: true, LatencyMS: 100, InputTokens: total / 2, OutputTokens: total / 2,
			TotalTokens: total,
		}
	}
	if _, err := repo.InsertUsageEvents(ctx, []usage.Event{
		event("a1", aliceSecret, "m1", day.Add(time.Hour), false, 100),
		event("a2", aliceSecret, "m2", day.Add(2*time.Hour), true, 10),
		event("a3", aliceSecret, "m1", day.Add(25*time.Hour), false, 50),
		event("x1", "sk-operator-own-key", "m1", day.Add(time.Hour), false, 999),
	}); err != nil {
		t.Fatal(err)
	}
	totals, err := repo.PortalUsageTotals(ctx, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if totals.Requests != 3 || totals.FailedRequests != 1 || totals.TotalTokens != 160 {
		t.Fatalf("alice totals = %+v", totals)
	}
	if bobTotals, _ := repo.PortalUsageTotals(ctx, bob.ID); bobTotals.Requests != 0 {
		t.Fatalf("bob was attributed someone else's usage: %+v", bobTotals)
	}
	byDay, err := repo.PortalUsageRollup(ctx, alice.ID, day.UnixMilli(), day.Add(48*time.Hour).UnixMilli(), PortalUsageByDay)
	if err != nil {
		t.Fatal(err)
	}
	if len(byDay) != 2 || byDay[0].Requests+byDay[1].Requests != 3 {
		t.Fatalf("alice by day = %+v", byDay)
	}
	byModel, err := repo.PortalUsageRollup(ctx, alice.ID, day.UnixMilli(), day.Add(48*time.Hour).UnixMilli(), PortalUsageByModel)
	if err != nil {
		t.Fatal(err)
	}
	models := map[string]int64{}
	for _, group := range byModel {
		models[group.Model] = group.Requests
	}
	if models["m1"] != 2 || models["m2"] != 1 {
		t.Fatalf("alice by model = %+v", byModel)
	}
	key, err := repo.GetPortalKey(ctx, aliceKey.ID)
	if err != nil {
		t.Fatal(err)
	}
	if key.RequestCount != 3 || key.LastUsedAtMS == nil {
		t.Fatalf("alice key usage = %+v", key)
	}

	page, err := repo.ListUsageEvents(ctx, UsageEventFilter{InstanceID: "default", PortalUserIDs: []string{fmt.Sprint(alice.ID)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 3 {
		t.Fatalf("records filtered to alice = %d, want 3", len(page.Items))
	}
	facet, err := repo.PortalUserFacet(ctx, "default", day.UnixMilli(), day.Add(48*time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if len(facet) != 1 || facet[0].Value != fmt.Sprint(alice.ID) || facet[0].Alias != "alice" || facet[0].Requests != 3 {
		t.Fatalf("portal user facet = %+v", facet)
	}
}
