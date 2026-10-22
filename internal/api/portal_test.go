package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oh-my-cpa/oh-my-cpa/internal/config"
	"github.com/oh-my-cpa/oh-my-cpa/internal/portal"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
	"github.com/oh-my-cpa/oh-my-cpa/internal/usage"
)

func init() {
	portal.PasswordIterations = 1000
}

// portalFakeKeys stands in for CPA's access.api-keys in the HTTP tests; the
// CPA-backed adapter is the same management write path the key page uses.
type portalFakeKeys struct {
	mu      sync.Mutex
	repo    func() *repository.Repository
	secrets map[string]string
}

func (f *portalFakeKeys) Fingerprints(context.Context) (map[string]struct{}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	result := map[string]struct{}{}
	for fp := range f.secrets {
		result[fp] = struct{}{}
	}
	return result, nil
}

func (f *portalFakeKeys) Add(_ context.Context, secret string) error {
	fp, err := f.repo().UsageClientKeyFingerprint(secret)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.secrets[fp] = secret
	return nil
}

func (f *portalFakeKeys) Remove(_ context.Context, fingerprint string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.secrets[fingerprint]
	delete(f.secrets, fingerprint)
	return ok, nil
}

func startPortalTestServer(t *testing.T, enabled bool) (*http.Client, string, *repository.Repository, *portalFakeKeys) {
	t.Helper()
	var handler *Handler
	keys := &portalFakeKeys{secrets: map[string]string{}, repo: func() *repository.Repository { return handler.repo }}
	admin, base, repo := startDashboardTestServer(t, nil, func(h *Handler) {
		handler = h
		h.cfg.Portal = config.PortalConfig{
			Enabled: enabled, Registration: config.PortalRegistrationInvite, SessionTTL: time.Hour,
			ShowCost: true, SyncInterval: time.Minute,
		}
		h.portalState.keys = keys
	})
	return admin, base, repo, keys
}

func newPortalClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar}
}

func decodeInto(t *testing.T, raw []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

func TestPortalCustomerFlowAndIsolation(t *testing.T) {
	admin, base, repo, keys := startPortalTestServer(t, true)
	api := base + "/omc/api"

	// The operator creates the customer.
	response, raw := doJSON(t, admin, http.MethodPost, api+"/v1/portal/users",
		`{"username":"alice","password":"password-1","display_name":"Alice","max_keys":3}`)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create user = %d %s", response.StatusCode, raw)
	}
	if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "pbkdf2") {
		t.Fatalf("user DTO leaks password material: %s", raw)
	}
	var created struct {
		User PortalAdminUserDTO `json:"user"`
	}
	decodeInto(t, raw, &created)

	customer := newPortalClient(t)
	// Not signed in: no portal data, and no operator data.
	if response, _ := getJSON(t, customer, api+"/portal/keys"); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous keys = %d", response.StatusCode)
	}
	if response, raw := doJSON(t, customer, http.MethodPost, api+"/portal/auth/login", `{"username":"alice","password":"nope-nope"}`); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password = %d %s", response.StatusCode, raw)
	}
	response, raw = doJSON(t, customer, http.MethodPost, api+"/portal/auth/login", `{"username":"ALICE","password":"password-1"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login = %d %s", response.StatusCode, raw)
	}
	var cookie *http.Cookie
	for _, c := range response.Cookies() {
		if c.Name == PortalSessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/omc" {
		t.Fatalf("portal cookie = %+v", cookie)
	}

	// A customer session never opens the operator API, and the operator's
	// session never signs anyone into the portal.
	for _, path := range []string{"/v1/portal/users", "/v1/usage/events", "/v1/management/audit/events"} {
		if response, _ := getJSON(t, customer, api+path); response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("customer reached %s: %d", path, response.StatusCode)
		}
	}
	if response, _ := getJSON(t, admin, api+"/portal/keys"); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("operator session reached the portal: %d", response.StatusCode)
	}

	// Cross-origin writes are refused.
	request, _ := http.NewRequest(http.MethodPost, api+"/portal/keys", strings.NewReader(`{"name":"x"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://evil.example")
	if response, err := customer.Do(request); err != nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin key create = %v %v", response.StatusCode, err)
	}

	// The key's plaintext is in the create response only.
	response, raw = doJSON(t, customer, http.MethodPost, api+"/portal/keys", `{"name":"laptop"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("create key = %d %s", response.StatusCode, raw)
	}
	var issued struct {
		Key    PortalKeyDTO `json:"key"`
		Secret string       `json:"secret"`
	}
	decodeInto(t, raw, &issued)
	if !strings.HasPrefix(issued.Secret, portal.KeyPrefix) || len(keys.secrets) != 1 {
		t.Fatalf("issued = %+v, CPA keys = %d", issued, len(keys.secrets))
	}
	for _, path := range []string{"/portal/keys", "/portal/usage/overview", "/portal/auth/session"} {
		_, body := getJSON(t, customer, api+path)
		if strings.Contains(string(body), issued.Secret) || strings.Contains(string(body), "hmac:") {
			t.Fatalf("%s exposes key material: %s", path, body)
		}
	}
	_, body := getJSON(t, admin, fmt.Sprintf("%s/v1/portal/users/%d/keys", api, created.User.ID))
	if strings.Contains(string(body), issued.Secret) || strings.Contains(string(body), "hmac:") {
		t.Fatalf("operator key list exposes key material: %s", body)
	}

	// A request made with the key is attributed to the customer.
	seedEvents(t, repo, time.Now(), []repository.UsageDecoded{{Event: func() usage.Event {
		event := eventFor("portal-req-1", time.Now().Add(-time.Minute), usage.TokenStats{InputTokens: 40, OutputTokens: 60, TotalTokens: 100}, false)
		event.APIGroupKey = issued.Secret
		ip := "203.0.113.9"
		event.ClientIP = &ip
		return event
	}()}, {Event: eventFor("operator-req-1", time.Now().Add(-time.Minute), usage.TokenStats{TotalTokens: 5}, false)}})

	_, body = getJSON(t, customer, api+"/portal/usage/overview?days=7")
	var overview struct {
		Lifetime PortalUsageMeasuresDTO `json:"lifetime"`
		Last24h  PortalUsageMeasuresDTO `json:"last_24h"`
		Models   []PortalUsageGroupDTO  `json:"models"`
		Keys     []PortalUsageGroupDTO  `json:"keys"`
	}
	decodeInto(t, body, &overview)
	if overview.Lifetime.Requests != 1 || overview.Lifetime.TotalTokens != 100 || overview.Last24h.Requests != 1 {
		t.Fatalf("overview = %s", body)
	}
	if len(overview.Keys) != 1 || overview.Keys[0].KeyName != "laptop" {
		t.Fatalf("overview keys = %+v", overview.Keys)
	}

	_, body = getJSON(t, customer, api+"/portal/usage/events")
	var events struct {
		Items []map[string]any `json:"items"`
	}
	decodeInto(t, body, &events)
	if len(events.Items) != 1 || events.Items[0]["key_name"] != "laptop" {
		t.Fatalf("customer events = %s", body)
	}
	for _, field := range []string{"provider", "auth_index", "endpoint", "client_ip", "api_group_key", "source", "user_agent"} {
		if _, present := events.Items[0][field]; present {
			t.Fatalf("customer record exposes %q: %s", field, body)
		}
	}
	if strings.Contains(string(body), "203.0.113.9") {
		t.Fatalf("customer record exposes the client address: %s", body)
	}

	// The operator narrows the request log to the customer.
	_, body = getJSON(t, admin, fmt.Sprintf("%s/v1/usage/events?portal_user=%d", api, created.User.ID))
	var adminEvents struct {
		Items []repository.UsageEventRow `json:"items"`
	}
	decodeInto(t, body, &adminEvents)
	if len(adminEvents.Items) != 1 || adminEvents.Items[0].RequestID != "portal-req-1" {
		t.Fatalf("operator filtered log = %s", body)
	}
	_, body = getJSON(t, admin, api+"/v1/usage/facets")
	var facets struct {
		Facets repository.UsageFacets `json:"facets"`
	}
	decodeInto(t, body, &facets)
	if len(facets.Facets.PortalUsers) != 1 || facets.Facets.PortalUsers[0].Alias != "alice" {
		t.Fatalf("portal user facet = %s", body)
	}

	// Revoking removes the key from CPA.
	response, raw = doJSON(t, customer, http.MethodDelete, fmt.Sprintf("%s/portal/keys/%d", api, issued.Key.ID), "")
	if response.StatusCode != http.StatusOK || len(keys.secrets) != 0 {
		t.Fatalf("revoke = %d %s, CPA keys = %d", response.StatusCode, raw, len(keys.secrets))
	}

	// Disabling the account ends the customer's session.
	response, raw = doJSON(t, admin, http.MethodPatch, fmt.Sprintf("%s/v1/portal/users/%d", api, created.User.ID), `{"status":"disabled"}`)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disable = %d %s", response.StatusCode, raw)
	}
	if response, _ := getJSON(t, customer, api+"/portal/keys"); response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled customer's session = %d", response.StatusCode)
	}

	// Every operator write was audited.
	_, body = getJSON(t, admin, api+"/v1/management/audit/events?limit=100")
	for _, action := range []string{"portal.user.create", "portal.key.create", "portal.key.revoke", "portal.user.update"} {
		if !strings.Contains(string(body), action) {
			t.Fatalf("audit log lacks %s", action)
		}
	}
	if strings.Contains(string(body), issued.Secret) || strings.Contains(string(body), "password-1") {
		t.Fatal("audit log contains a secret")
	}
}

func TestPortalInviteRegistration(t *testing.T) {
	admin, base, _, _ := startPortalTestServer(t, true)
	api := base + "/omc/api"
	_, body := getJSON(t, newPortalClient(t), api+"/portal/config")
	if !strings.Contains(string(body), `"registration":"invite"`) {
		t.Fatalf("config = %s", body)
	}
	response, raw := doJSON(t, admin, http.MethodPost, api+"/v1/portal/invites", `{"max_uses":1,"note":"for bob"}`)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("invite = %d %s", response.StatusCode, raw)
	}
	var invite struct {
		Code string `json:"code"`
	}
	decodeInto(t, raw, &invite)
	_, list := getJSON(t, admin, api+"/v1/portal/invites")
	if strings.Contains(string(list), invite.Code) {
		t.Fatalf("invite list exposes the code: %s", list)
	}
	customer := newPortalClient(t)
	response, raw = doJSON(t, customer, http.MethodPost, api+"/portal/auth/register",
		fmt.Sprintf(`{"username":"bob","password":"password-2","invite_code":%q}`, invite.Code))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("register = %d %s", response.StatusCode, raw)
	}
	if response, _ := getJSON(t, customer, api+"/portal/keys"); response.StatusCode != http.StatusOK {
		t.Fatalf("registered customer is not signed in: %d", response.StatusCode)
	}
	response, raw = doJSON(t, newPortalClient(t), http.MethodPost, api+"/portal/auth/register",
		fmt.Sprintf(`{"username":"mallory","password":"password-3","invite_code":%q}`, invite.Code))
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(raw), "invite_invalid") {
		t.Fatalf("spent invite = %d %s", response.StatusCode, raw)
	}
}

func TestPortalDisabledByDefault(t *testing.T) {
	admin, base, _, _ := startPortalTestServer(t, false)
	api := base + "/omc/api"
	_, body := getJSON(t, newPortalClient(t), api+"/portal/config")
	if strings.TrimSpace(string(body)) != `{"enabled":false}` {
		t.Fatalf("disabled config = %s", body)
	}
	response, raw := doJSON(t, newPortalClient(t), http.MethodPost, api+"/portal/auth/login", `{"username":"a","password":"b"}`)
	if response.StatusCode != http.StatusNotFound || !strings.Contains(string(raw), "portal_disabled") {
		t.Fatalf("disabled login = %d %s", response.StatusCode, raw)
	}
	response, raw = doJSON(t, admin, http.MethodPost, api+"/v1/portal/users", `{"username":"alice","password":"password-1"}`)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("disabled create = %d %s", response.StatusCode, raw)
	}
	if response, _ := getJSON(t, admin, api+"/v1/portal/status"); response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}
