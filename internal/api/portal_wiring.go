package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/oh-my-cpa/oh-my-cpa/internal/portal"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
)

// The customer portal (ADR 0105) is mounted from this file so the shared router
// carries two lines for it: the customer surface under /api/portal and the
// operator's account management under /api/v1/portal.

// PortalSessionCookie is the customer session cookie. It is a different cookie
// from the operator's omc_session, and neither middleware reads the other's:
// a customer session can never reach /api/v1, and the operator's session does
// not sign anyone into the portal.
const PortalSessionCookie = "omc_portal_session"

// portalState is the handler's portal wiring, built on first use.
type portalState struct {
	once    sync.Once
	service *portal.Service
	// keys replaces the CPA-backed key store; tests set it before first use.
	keys portal.KeyStore
	// limiter throttles failed customer sign-ins per client address, separately
	// from the operator's sign-in limiter.
	limiter *loginLimiter
	// signups throttles registrations per client address.
	signups *portalSignupLimiter
}

func (h *Handler) portalService() *portal.Service {
	h.portalState.once.Do(func() {
		keys := h.portalState.keys
		if keys == nil {
			keys = &cpaPortalKeyStore{handler: h}
		}
		h.portalState.limiter = newLoginLimiter()
		h.portalState.signups = newPortalSignupLimiter()
		h.portalState.service = &portal.Service{
			Repo:   h.repo,
			Keys:   keys,
			Config: h.cfg.Portal,
			Logger: h.logger,
			Alias: func(ctx context.Context, fingerprint, alias string) {
				// Best effort: the alias only labels the operator's own key page and
				// request filters; the key works without it.
				if _, err := h.repo.SetClientKeyAlias(ctx, defaultInstanceID(), fingerprint, alias, 0); err != nil && h.logger != nil {
					h.logger.Warn("could not name a portal key in the caller-key list", "error", err.Error())
				}
			},
		}
	})
	return h.portalState.service
}

// RunPortalSync runs the portal's key reconciler until ctx ends. It returns at
// once when the portal is disabled.
func (h *Handler) RunPortalSync(ctx context.Context) error {
	if !h.cfg.Portal.Enabled || h.cfg.IsDemoMode {
		return nil
	}
	return h.portalService().Run(ctx)
}

// cpaPortalKeyStore is CPA's access.api-keys through the same management
// operations the console's own key page uses, so a portal write takes the
// provider write gate, the revision check and the pre-write configuration
// backup like any other key edit.
type cpaPortalKeyStore struct {
	handler *Handler
}

func (s *cpaPortalKeyStore) Fingerprints(ctx context.Context) (map[string]struct{}, error) {
	client, err := s.handler.capabilityClient(ctx)
	if err != nil {
		return nil, err
	}
	keys, err := client.ClientAPIKeys(ctx)
	if err != nil {
		return nil, err
	}
	result := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		if fingerprint, fpErr := s.handler.repo.UsageClientKeyFingerprint(strings.TrimSpace(key)); fpErr == nil {
			result[fingerprint] = struct{}{}
		}
	}
	return result, nil
}

func (s *cpaPortalKeyStore) Add(ctx context.Context, secret string) error {
	_, err := s.handler.operationsService().CreateKey(ctx, secret, "")
	return err
}

func (s *cpaPortalKeyStore) Remove(ctx context.Context, fingerprint string) (bool, error) {
	client, err := s.handler.capabilityClient(ctx)
	if err != nil {
		return false, err
	}
	keys, err := client.ClientAPIKeys(ctx)
	if err != nil {
		return false, err
	}
	for index, key := range keys {
		actual, fpErr := s.handler.repo.UsageClientKeyFingerprint(strings.TrimSpace(key))
		if fpErr != nil || actual != fingerprint {
			continue
		}
		// DeleteKey re-reads the list under the write gate and refuses if the
		// entry at this index no longer carries this fingerprint, so a concurrent
		// edit cannot make it delete the operator's key.
		if err := s.handler.operationsService().DeleteKey(ctx, index, fingerprint, ""); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// mountPortalRoutes registers the customer surface under <base>/api/portal.
func (h *Handler) mountPortalRoutes(router chi.Router) {
	router.Route("/portal", func(r chi.Router) {
		r.Get("/config", h.portalConfig)
		r.Group(func(public chi.Router) {
			public.Use(h.requirePortalEnabled)
			public.Post("/auth/login", h.portalLogin)
			public.Post("/auth/register", h.portalRegister)
			public.Post("/auth/logout", h.portalLogout)
			public.Get("/auth/session", h.portalSession)
		})
		r.Group(func(private chi.Router) {
			private.Use(h.requirePortalEnabled, h.requirePortalSession)
			private.Put("/me/password", h.portalChangePassword)
			private.Get("/keys", h.portalListKeys)
			private.Post("/keys", h.portalCreateKey)
			private.Delete("/keys/{id}", h.portalRevokeKey)
			private.Get("/usage/overview", h.portalUsageOverview)
			private.Get("/usage/events", h.portalUsageEvents)
		})
		r.NotFound(h.notFound)
		r.MethodNotAllowed(h.methodNotAllowed)
	})
}

// mountPortalAdminRoutes registers the operator's account management. It runs
// inside /api/v1, behind the operator's session.
func (h *Handler) mountPortalAdminRoutes(v1 chi.Router) {
	v1.Get("/portal/status", h.adminPortalStatus)
	v1.Get("/portal/users", h.adminListPortalUsers)
	v1.Post("/portal/users", h.adminCreatePortalUser)
	v1.Patch("/portal/users/{id}", h.adminUpdatePortalUser)
	v1.Get("/portal/users/{id}/keys", h.adminListPortalUserKeys)
	v1.Get("/portal/users/{id}/usage", h.adminPortalUserUsage)
	v1.Delete("/portal/keys/{id}", h.adminRevokePortalKey)
	v1.Get("/portal/invites", h.adminListPortalInvites)
	v1.Post("/portal/invites", h.adminCreatePortalInvite)
	v1.Delete("/portal/invites/{id}", h.adminRevokePortalInvite)
	v1.Post("/portal/sync", h.adminPortalSync)
}

func init() {
	// The demonstration has no gateway to issue customer keys against, so the
	// portal is disabled there (config.Load) and every portal route, read or
	// write, is refused: the static demo export carries no portal responses, and
	// the operator page renders its unavailable state from the refusal.
	const refused = "The customer portal is unavailable in the demo"
	demoPolicy = append(demoPolicy,
		demoPolicyRule{http.MethodGet, "/api/portal/config", demoRefuse, refused},
		demoPolicyRule{http.MethodPost, "/api/portal/auth/login", demoRefuse, refused},
		demoPolicyRule{http.MethodPost, "/api/portal/auth/register", demoRefuse, refused},
		demoPolicyRule{http.MethodPost, "/api/portal/auth/logout", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/portal/auth/session", demoRefuse, refused},
		demoPolicyRule{http.MethodPut, "/api/portal/me/password", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/portal/keys", demoRefuse, refused},
		demoPolicyRule{http.MethodPost, "/api/portal/keys", demoRefuse, refused},
		demoPolicyRule{http.MethodDelete, "/api/portal/keys/{id}", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/portal/usage/overview", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/portal/usage/events", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/v1/portal/status", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/v1/portal/users", demoRefuse, refused},
		demoPolicyRule{http.MethodPost, "/api/v1/portal/users", demoRefuse, refused},
		demoPolicyRule{http.MethodPatch, "/api/v1/portal/users/{id}", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/v1/portal/users/{id}/keys", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/v1/portal/users/{id}/usage", demoRefuse, refused},
		demoPolicyRule{http.MethodDelete, "/api/v1/portal/keys/{id}", demoRefuse, refused},
		demoPolicyRule{http.MethodGet, "/api/v1/portal/invites", demoRefuse, refused},
		demoPolicyRule{http.MethodPost, "/api/v1/portal/invites", demoRefuse, refused},
		demoPolicyRule{http.MethodDelete, "/api/v1/portal/invites/{id}", demoRefuse, refused},
		demoPolicyRule{http.MethodPost, "/api/v1/portal/sync", demoRefuse, refused},
	)
}

// portalSignupLimiter allows a few registrations per client address per hour.
type portalSignupLimiter struct {
	mu      sync.Mutex
	windows map[string]portalSignupWindow
}

type portalSignupWindow struct {
	start time.Time
	count int
}

const (
	portalSignupsPerHour = 5
	portalSignupTracked  = 5000
)

func newPortalSignupLimiter() *portalSignupLimiter {
	return &portalSignupLimiter{windows: map[string]portalSignupWindow{}}
}

// allow records one attempt and reports whether it is within the limit.
func (l *portalSignupLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	window := l.windows[ip]
	if now.Sub(window.start) > time.Hour {
		window = portalSignupWindow{start: now}
	}
	if len(l.windows) >= portalSignupTracked {
		for key, entry := range l.windows {
			if now.Sub(entry.start) > time.Hour {
				delete(l.windows, key)
			}
		}
	}
	window.count++
	l.windows[ip] = window
	return window.count <= portalSignupsPerHour
}

// portalErrorStatus maps a portal error code to its HTTP status.
func portalErrorStatus(err error) (int, string) {
	codes := []struct {
		err    error
		status int
	}{
		{portal.ErrInvalidCredentials, http.StatusUnauthorized},
		{portal.ErrSessionInvalid, http.StatusUnauthorized},
		{portal.ErrRegistrationClosed, http.StatusForbidden},
		{portal.ErrInviteRequired, http.StatusBadRequest},
		{portal.ErrInviteInvalid, http.StatusForbidden},
		{portal.ErrUsernameTaken, http.StatusConflict},
		{portal.ErrKeyLimit, http.StatusConflict},
		{portal.ErrGatewaySync, http.StatusBadGateway},
		{portal.ErrKeyStoreUnavailable, http.StatusServiceUnavailable},
		{portal.ErrNotFound, http.StatusNotFound},
		{portal.ErrInvalidUsername, http.StatusBadRequest},
		{portal.ErrInvalidPassword, http.StatusBadRequest},
		{portal.ErrInvalidDisplayName, http.StatusBadRequest},
		{portal.ErrInvalidKeyName, http.StatusBadRequest},
		{portal.ErrInvalidExpiry, http.StatusBadRequest},
		{portal.ErrInvalidNote, http.StatusBadRequest},
		{portal.ErrInvalidMaxKeys, http.StatusBadRequest},
		{portal.ErrInvalidStatus, http.StatusBadRequest},
		{portal.ErrInvalidInviteRequest, http.StatusBadRequest},
	}
	for _, code := range codes {
		if errors.Is(err, code.err) {
			return code.status, code.err.Error()
		}
	}
	return http.StatusInternalServerError, "internal_error"
}

func (h *Handler) writePortalError(writer http.ResponseWriter, err error) {
	status, code := portalErrorStatus(err)
	if status == http.StatusInternalServerError {
		writeInternalError(writer, err)
		return
	}
	if status == http.StatusBadGateway && h.logger != nil {
		h.logger.Warn("portal gateway write failed", "error", err.Error())
	}
	writeJSON(writer, status, map[string]string{"error": code, "code": code})
}

// portalUserFromContext is the signed-in customer.
type portalContextKey struct{}

type portalPrincipal struct {
	user        repository.PortalUser
	sessionHash string
}

func portalPrincipalFrom(request *http.Request) (portalPrincipal, bool) {
	principal, ok := request.Context().Value(portalContextKey{}).(portalPrincipal)
	return principal, ok
}

// attachPortalUserFacet adds the customer accounts present in a window to the
// request-log facets, so the operator can narrow the log to one customer. It is
// best effort like the alias labels: a failure leaves the facet empty.
func (h *Handler) attachPortalUserFacet(request *http.Request, fromMS, toMS int64, facets *repository.UsageFacets) {
	if h.repo == nil || facets == nil {
		return
	}
	values, err := h.repo.PortalUserFacet(request.Context(), defaultInstanceID(), fromMS, toMS)
	facets.PortalUsers = []repository.UsageFacetValue{}
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("could not list portal users for the request-log filter", "error", err.Error())
		}
		return
	}
	facets.PortalUsers = values
}
