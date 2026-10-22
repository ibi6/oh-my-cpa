package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/oh-my-cpa/oh-my-cpa/internal/portal"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
)

// PortalUserDTO is what a customer sees of their own account, and the
// operator of any account. The password hash and auth version never leave.
type PortalUserDTO struct {
	ID            int64  `json:"id"`
	Username      string `json:"username"`
	DisplayName   string `json:"display_name"`
	Status        string `json:"status"`
	MaxKeys       int    `json:"max_keys"`
	CreatedAtMS   int64  `json:"created_at_ms"`
	LastLoginAtMS *int64 `json:"last_login_at_ms,omitempty"`
}

func portalUserDTO(user repository.PortalUser) PortalUserDTO {
	return PortalUserDTO{
		ID: user.ID, Username: user.Username, DisplayName: user.DisplayName, Status: user.Status,
		MaxKeys: user.MaxKeys, CreatedAtMS: user.CreatedAtMS, LastLoginAtMS: user.LastLoginAtMS,
	}
}

// PortalKeyDTO is one key as its owner and the operator see it: the display
// prefix and tail, never the fingerprint or the plaintext.
type PortalKeyDTO struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Prefix       string `json:"prefix"`
	Last4        string `json:"last4"`
	Status       string `json:"status"`
	State        string `json:"state"`
	SyncState    string `json:"sync_state"`
	ExpiresAtMS  *int64 `json:"expires_at_ms,omitempty"`
	RequestCount int64  `json:"request_count"`
	LastUsedAtMS *int64 `json:"last_used_at_ms,omitempty"`
	CreatedAtMS  int64  `json:"created_at_ms"`
	RevokedAtMS  *int64 `json:"revoked_at_ms,omitempty"`
}

// portalKeyState is the one word a key's row leads with: whether it works now.
func portalKeyState(key repository.PortalKey, nowMS int64) string {
	switch {
	case key.Status == repository.PortalKeyRevoked:
		return "revoked"
	case key.ExpiresAtMS != nil && *key.ExpiresAtMS <= nowMS:
		return "expired"
	case key.UserStatus != "" && key.UserStatus != repository.PortalUserActive:
		return "suspended"
	case key.SyncState == repository.PortalSyncMissing:
		return "missing"
	case key.SyncState == repository.PortalSyncFailed || key.SyncState == repository.PortalSyncPending:
		return "pending"
	default:
		return "active"
	}
}

func portalKeyDTO(key repository.PortalKey, nowMS int64) PortalKeyDTO {
	return PortalKeyDTO{
		ID: key.ID, Name: key.Name, Prefix: key.Prefix, Last4: key.Last4, Status: key.Status,
		State: portalKeyState(key, nowMS), SyncState: key.SyncState, ExpiresAtMS: key.ExpiresAtMS,
		RequestCount: key.RequestCount, LastUsedAtMS: key.LastUsedAtMS, CreatedAtMS: key.CreatedAtMS,
		RevokedAtMS: key.RevokedAtMS,
	}
}

func (h *Handler) portalCookiePath() string {
	if h.cfg.BasePath == "" {
		return "/"
	}
	return h.cfg.BasePath
}

func (h *Handler) portalCookieSecure() bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(h.cfg.PublicURL)), "https://")
}

func (h *Handler) setPortalCookie(writer http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(writer, &http.Cookie{
		Name: PortalSessionCookie, Value: token, Path: h.portalCookiePath(), HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: h.portalCookieSecure(), Expires: expires,
	})
}

func (h *Handler) clearPortalCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name: PortalSessionCookie, Value: "", Path: h.portalCookiePath(), HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: h.portalCookieSecure(), Expires: time.Unix(0, 0), MaxAge: -1,
	})
}

func portalCookieValue(request *http.Request) string {
	cookie, err := request.Cookie(PortalSessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *Handler) requirePortalEnabled(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		if !h.cfg.Portal.Enabled || h.cfg.IsDemoMode {
			writeJSON(writer, http.StatusNotFound, map[string]string{"error": "portal_disabled", "code": "portal_disabled"})
			return
		}
		if request.Method != http.MethodGet && request.Method != http.MethodHead && !sameOrigin(request) {
			writeError(writer, http.StatusForbidden, "same-origin request required")
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (h *Handler) requirePortalSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		user, sessionHash, err := h.portalService().ResolveSession(request.Context(), portalCookieValue(request))
		if err != nil {
			if errors.Is(err, portal.ErrSessionInvalid) {
				writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "authentication required", "code": "session_invalid"})
				return
			}
			writeInternalError(writer, err)
			return
		}
		ctx := context.WithValue(request.Context(), portalContextKey{}, portalPrincipal{user: user, sessionHash: sessionHash})
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// portalConfig is public: the sign-in page needs to know whether to offer
// registration and whether an invite is required.
func (h *Handler) portalConfig(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	enabled := h.cfg.Portal.Enabled && !h.cfg.IsDemoMode
	payload := map[string]any{"enabled": enabled}
	if enabled {
		payload["registration"] = h.cfg.Portal.Registration
		payload["gateway_url"] = h.cfg.Portal.GatewayURL
		payload["show_cost"] = h.cfg.Portal.ShowCost
	}
	writeJSON(writer, http.StatusOK, payload)
}

type portalLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *Handler) portalLogin(writer http.ResponseWriter, request *http.Request) {
	service := h.portalService()
	ip := resolveClientIP(request, h.trustedProxies)
	if h.portalState.limiter.isLocked(ip) {
		writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "too_many_attempts", "code": "too_many_attempts"})
		return
	}
	var payload portalLoginRequest
	if err := decodeManagementJSON(writer, request, 8*1024, &payload); err != nil {
		return
	}
	user, err := service.Authenticate(request.Context(), payload.Username, payload.Password)
	if err != nil {
		if errors.Is(err, portal.ErrInvalidCredentials) {
			h.portalState.limiter.recordFailure(ip)
		}
		h.writePortalError(writer, err)
		return
	}
	h.portalState.limiter.reset(ip)
	h.startPortalSession(writer, request, user)
}

func (h *Handler) startPortalSession(writer http.ResponseWriter, request *http.Request, user repository.PortalUser) {
	token, expires, err := h.portalService().IssueSession(request.Context(), user,
		resolveClientIP(request, h.trustedProxies), request.UserAgent())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	h.setPortalCookie(writer, token, expires)
	writeJSON(writer, http.StatusOK, map[string]any{"authenticated": true, "user": portalUserDTO(user)})
}

type portalRegisterRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	InviteCode  string `json:"invite_code"`
}

func (h *Handler) portalRegister(writer http.ResponseWriter, request *http.Request) {
	service := h.portalService()
	if h.cfg.Portal.Registration == "" || h.cfg.Portal.Registration == "off" {
		h.writePortalError(writer, portal.ErrRegistrationClosed)
		return
	}
	if !h.portalState.signups.allow(resolveClientIP(request, h.trustedProxies), time.Now()) {
		writeJSON(writer, http.StatusTooManyRequests, map[string]string{"error": "too_many_attempts", "code": "too_many_attempts"})
		return
	}
	var payload portalRegisterRequest
	if err := decodeManagementJSON(writer, request, 8*1024, &payload); err != nil {
		return
	}
	details := map[string]any{"actor": "portal_user", "username": payload.Username, "mode": h.cfg.Portal.Registration}
	if err := h.recordAudit(request, "portal.user.register", "portal_user", payload.Username, "attempt", details); err != nil {
		writeAuditFailure(writer, "audit log failure; registration aborted")
		return
	}
	user, err := service.Register(request.Context(), portal.NewUser{
		Username: payload.Username, Password: payload.Password, DisplayName: payload.DisplayName,
		InviteCode: payload.InviteCode,
	})
	if err != nil {
		_ = h.recordAudit(request, "portal.user.register", "portal_user", payload.Username, "failure", mergeDetails(details, map[string]any{"error": err.Error()}))
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.user.register", "portal_user", strconv.FormatInt(user.ID, 10), "success", details)
	h.startPortalSession(writer, request, user)
}

func (h *Handler) portalLogout(writer http.ResponseWriter, request *http.Request) {
	_ = h.portalService().EndSession(request.Context(), portalCookieValue(request))
	h.clearPortalCookie(writer)
	writeJSON(writer, http.StatusOK, map[string]any{"authenticated": false})
}

func (h *Handler) portalSession(writer http.ResponseWriter, request *http.Request) {
	user, _, err := h.portalService().ResolveSession(request.Context(), portalCookieValue(request))
	if err != nil {
		if errors.Is(err, portal.ErrSessionInvalid) {
			writeJSON(writer, http.StatusOK, map[string]any{"authenticated": false})
			return
		}
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"authenticated": true, "user": portalUserDTO(user)})
}

type portalPasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *Handler) portalChangePassword(writer http.ResponseWriter, request *http.Request) {
	principal, _ := portalPrincipalFrom(request)
	var payload portalPasswordRequest
	if err := decodeManagementJSON(writer, request, 8*1024, &payload); err != nil {
		return
	}
	target := strconv.FormatInt(principal.user.ID, 10)
	details := map[string]any{"actor": "portal_user", "username": principal.user.Username}
	if err := h.recordAudit(request, "portal.user.password", "portal_user", target, "attempt", details); err != nil {
		writeAuditFailure(writer, "audit log failure; password change aborted")
		return
	}
	if err := h.portalService().ChangePassword(request.Context(), principal.user, principal.sessionHash,
		payload.CurrentPassword, payload.NewPassword); err != nil {
		_ = h.recordAudit(request, "portal.user.password", "portal_user", target, "failure", mergeDetails(details, map[string]any{"error": err.Error()}))
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.user.password", "portal_user", target, "success", details)
	writeJSON(writer, http.StatusOK, map[string]any{"status": "ok"})
}

func (h *Handler) portalListKeys(writer http.ResponseWriter, request *http.Request) {
	principal, _ := portalPrincipalFrom(request)
	keys, err := h.repo.ListPortalKeys(request.Context(), principal.user.ID)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	nowMS := time.Now().UnixMilli()
	items := make([]PortalKeyDTO, 0, len(keys))
	active := 0
	for _, key := range keys {
		items = append(items, portalKeyDTO(key, nowMS))
		if key.Status == repository.PortalKeyActive {
			active++
		}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"keys": items, "max_keys": principal.user.MaxKeys, "active_keys": active})
}

type portalCreateKeyRequest struct {
	Name        string `json:"name"`
	ExpiresAtMS *int64 `json:"expires_at_ms"`
}

func (h *Handler) portalCreateKey(writer http.ResponseWriter, request *http.Request) {
	principal, _ := portalPrincipalFrom(request)
	var payload portalCreateKeyRequest
	if err := decodeManagementJSON(writer, request, 8*1024, &payload); err != nil {
		return
	}
	target := strconv.FormatInt(principal.user.ID, 10)
	details := map[string]any{"actor": "portal_user", "user_id": principal.user.ID, "username": principal.user.Username}
	// The write reaches CPA's configuration, so it is audited like the
	// operator's own key creation: no audit row, no write.
	if err := h.recordAudit(request, "portal.key.create", "portal_user", target, "attempt", details); err != nil {
		writeAuditFailure(writer, "audit log failure; key creation aborted")
		return
	}
	created, err := h.portalService().CreateKey(request.Context(), principal.user, payload.Name, payload.ExpiresAtMS)
	if err != nil {
		_ = h.recordAudit(request, "portal.key.create", "portal_user", target, "failure", mergeDetails(details, map[string]any{"error": err.Error()}))
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.key.create", "portal_user", target, "success", mergeDetails(details, map[string]any{"key_id": created.Key.ID}))
	// The plaintext is in this one response and nowhere else; the client is
	// told so it can warn the customer to copy it now.
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusOK, map[string]any{
		"key":    portalKeyDTO(created.Key, time.Now().UnixMilli()),
		"secret": created.Secret,
	})
}

func mergeDetails(base map[string]any, extra map[string]any) map[string]any {
	merged := make(map[string]any, len(base)+len(extra))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}

func portalIDParam(request *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(request, "id"), 10, 64)
	return id, err == nil && id > 0
}

func (h *Handler) portalRevokeKey(writer http.ResponseWriter, request *http.Request) {
	principal, _ := portalPrincipalFrom(request)
	id, ok := portalIDParam(request)
	if !ok {
		h.writePortalError(writer, portal.ErrNotFound)
		return
	}
	details := map[string]any{"actor": "portal_user", "user_id": principal.user.ID, "username": principal.user.Username}
	if err := h.recordAudit(request, "portal.key.revoke", "portal_key", strconv.FormatInt(id, 10), "attempt", details); err != nil {
		writeAuditFailure(writer, "audit log failure; key revocation aborted")
		return
	}
	key, err := h.portalService().RevokeKey(request.Context(), id, principal.user.ID)
	if err != nil {
		_ = h.recordAudit(request, "portal.key.revoke", "portal_key", strconv.FormatInt(id, 10), "failure", details)
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.key.revoke", "portal_key", strconv.FormatInt(id, 10), "success", details)
	writeJSON(writer, http.StatusOK, map[string]any{"key": portalKeyDTO(key, time.Now().UnixMilli())})
}

// PortalUsageMeasuresDTO is a usage total as the portal shows it.
type PortalUsageMeasuresDTO struct {
	Requests        int64    `json:"requests"`
	FailedRequests  int64    `json:"failed_requests"`
	InputTokens     int64    `json:"input_tokens"`
	OutputTokens    int64    `json:"output_tokens"`
	ReasoningTokens int64    `json:"reasoning_tokens"`
	CachedTokens    int64    `json:"cached_tokens"`
	TotalTokens     int64    `json:"total_tokens"`
	CostUSD         *float64 `json:"cost_usd,omitempty"`
}

// PortalUsageGroupDTO is one row of a usage breakdown.
type PortalUsageGroupDTO struct {
	DayStartMS int64  `json:"day_start_ms,omitempty"`
	Model      string `json:"model,omitempty"`
	KeyID      int64  `json:"key_id,omitempty"`
	KeyName    string `json:"key_name,omitempty"`
	PortalUsageMeasuresDTO
}

func (h *Handler) portalMeasures(m repository.PortalUsageMeasures, showCost bool) PortalUsageMeasuresDTO {
	dto := PortalUsageMeasuresDTO{
		Requests: m.Requests, FailedRequests: m.FailedRequests, InputTokens: m.InputTokens,
		OutputTokens: m.OutputTokens, ReasoningTokens: m.ReasoningTokens, CachedTokens: m.CachedTokens,
		TotalTokens: m.TotalTokens,
	}
	if showCost {
		cost := float64(m.CostNanos) / 1e9
		dto.CostUSD = &cost
	}
	return dto
}

const portalDayMS = int64(24 * time.Hour / time.Millisecond)

// portalUsageReport builds the overview a customer (or the operator, for one
// customer) reads: lifetime totals, the last 24 hours, and the last N UTC days
// by day, model and key.
func (h *Handler) portalUsageReport(ctx context.Context, userID int64, days int, showCost bool) (map[string]any, error) {
	if days < 1 || days > 366 {
		days = 30
	}
	now := time.Now().UTC()
	todayMS := (now.UnixMilli() / portalDayMS) * portalDayMS
	fromDayMS := todayMS - int64(days-1)*portalDayMS
	lifetime, err := h.repo.PortalUsageTotals(ctx, userID)
	if err != nil {
		return nil, err
	}
	recent, err := h.repo.PortalRecentUsage(ctx, userID, now.Add(-24*time.Hour).UnixMilli(), now.UnixMilli())
	if err != nil {
		return nil, err
	}
	keys, err := h.repo.ListPortalKeys(ctx, userID)
	if err != nil {
		return nil, err
	}
	keyNames := make(map[int64]string, len(keys))
	for _, key := range keys {
		keyNames[key.ID] = key.Name
	}
	result := map[string]any{
		"window":   map[string]any{"from_day_ms": fromDayMS, "to_day_ms": todayMS, "days": days, "timezone": "UTC"},
		"lifetime": h.portalMeasures(lifetime, showCost),
		"last_24h": h.portalMeasures(recent, showCost),
	}
	var windowTotals repository.PortalUsageMeasures
	for _, grouping := range []string{repository.PortalUsageByDay, repository.PortalUsageByModel, repository.PortalUsageByKey} {
		groups, err := h.repo.PortalUsageRollup(ctx, userID, fromDayMS, todayMS, grouping)
		if err != nil {
			return nil, err
		}
		items := make([]PortalUsageGroupDTO, 0, len(groups))
		for _, group := range groups {
			item := PortalUsageGroupDTO{
				DayStartMS: group.DayStartMS, Model: group.Model, KeyID: group.KeyID,
				PortalUsageMeasuresDTO: h.portalMeasures(group.PortalUsageMeasures, showCost),
			}
			if grouping == repository.PortalUsageByKey {
				item.KeyName = keyNames[group.KeyID]
			}
			if grouping == repository.PortalUsageByDay {
				windowTotals.Requests += group.Requests
				windowTotals.FailedRequests += group.FailedRequests
				windowTotals.InputTokens += group.InputTokens
				windowTotals.OutputTokens += group.OutputTokens
				windowTotals.ReasoningTokens += group.ReasoningTokens
				windowTotals.CachedTokens += group.CachedTokens
				windowTotals.TotalTokens += group.TotalTokens
				windowTotals.CostNanos += group.CostNanos
			}
			items = append(items, item)
		}
		result[map[string]string{
			repository.PortalUsageByDay: "daily", repository.PortalUsageByModel: "models", repository.PortalUsageByKey: "keys",
		}[grouping]] = items
	}
	result["totals"] = h.portalMeasures(windowTotals, showCost)
	return result, nil
}

func portalDaysParam(request *http.Request) int {
	days, err := strconv.Atoi(strings.TrimSpace(request.URL.Query().Get("days")))
	if err != nil {
		return 30
	}
	return days
}

func (h *Handler) portalUsageOverview(writer http.ResponseWriter, request *http.Request) {
	principal, _ := portalPrincipalFrom(request)
	report, err := h.portalUsageReport(request.Context(), principal.user.ID, portalDaysParam(request), h.cfg.Portal.ShowCost)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, report)
}

// PortalUsageEventDTO is one request record as its customer sees it. It is a
// strict subset of the operator's row: no provider, credential, endpoint,
// client address, user agent or upstream error body.
type PortalUsageEventDTO struct {
	ID              int64    `json:"id"`
	TimestampMS     int64    `json:"timestamp_ms"`
	KeyID           int64    `json:"key_id,omitempty"`
	KeyName         string   `json:"key_name,omitempty"`
	Model           string   `json:"model"`
	Failed          bool     `json:"failed"`
	StatusCode      int      `json:"status_code,omitempty"`
	Stream          *bool    `json:"stream,omitempty"`
	LatencyMS       int64    `json:"latency_ms"`
	TTFTMS          *int64   `json:"ttft_ms,omitempty"`
	InputTokens     int64    `json:"input_tokens"`
	OutputTokens    int64    `json:"output_tokens"`
	ReasoningTokens int64    `json:"reasoning_tokens"`
	CachedTokens    int64    `json:"cached_tokens"`
	TotalTokens     int64    `json:"total_tokens"`
	CostUSD         *float64 `json:"cost_usd,omitempty"`
	RequestID       string   `json:"request_id,omitempty"`
}

func (h *Handler) portalUsageEvents(writer http.ResponseWriter, request *http.Request) {
	principal, _ := portalPrincipalFrom(request)
	query := request.URL.Query()
	keys, err := h.repo.ListPortalKeys(request.Context(), principal.user.ID)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	byFingerprint := make(map[string]repository.PortalKey, len(keys))
	byID := make(map[int64]repository.PortalKey, len(keys))
	for _, key := range keys {
		byFingerprint[key.Fingerprint] = key
		byID[key.ID] = key
	}
	filter := repository.UsageEventFilter{
		InstanceID:    defaultInstanceID(),
		PortalUserIDs: []string{strconv.FormatInt(principal.user.ID, 10)},
		Cursor:        query.Get("cursor"),
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		if limit, convErr := strconv.Atoi(raw); convErr == nil {
			filter.Limit = limit
		}
	}
	if raw := strings.TrimSpace(query.Get("key_id")); raw != "" {
		id, convErr := strconv.ParseInt(raw, 10, 64)
		key, owned := byID[id]
		if convErr != nil || !owned {
			writeError(writer, http.StatusBadRequest, "unknown key")
			return
		}
		filter.APIGroupKeys = []string{key.Fingerprint}
	}
	if model := strings.TrimSpace(query.Get("model")); model != "" {
		if len(model) > 256 {
			writeError(writer, http.StatusBadRequest, "model is too long")
			return
		}
		filter.Models = []string{model}
	}
	switch strings.TrimSpace(query.Get("result")) {
	case "", repository.ResultAll:
	case repository.ResultSuccess, repository.ResultFailed:
		filter.Result = query.Get("result")
	default:
		writeError(writer, http.StatusBadRequest, "result must be one of all, success or failed")
		return
	}
	page, err := h.repo.ListUsageEvents(request.Context(), filter)
	if err != nil {
		h.writeUsageQueryError(writer, err)
		return
	}
	items := make([]PortalUsageEventDTO, 0, len(page.Items))
	for _, row := range page.Items {
		item := PortalUsageEventDTO{
			ID: row.ID, TimestampMS: row.TimestampMS, Model: row.Model, Failed: row.Failed,
			StatusCode: row.FailStatusCode, Stream: row.Stream, LatencyMS: row.LatencyMS, TTFTMS: row.TTFTMS,
			InputTokens: row.Tokens.InputTokens, OutputTokens: row.Tokens.OutputTokens,
			ReasoningTokens: row.Tokens.ReasoningTokens, CachedTokens: row.Tokens.CachedTokens,
			TotalTokens: row.Tokens.TotalTokens, RequestID: row.RequestID,
		}
		if row.ModelAlias != nil && strings.TrimSpace(*row.ModelAlias) != "" {
			item.Model = *row.ModelAlias
		}
		if key, ok := byFingerprint[row.APIGroupKey]; ok {
			item.KeyID = key.ID
			item.KeyName = key.Name
		}
		if h.cfg.Portal.ShowCost {
			item.CostUSD = row.CostUSD
		}
		items = append(items, item)
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"items": items, "next_cursor": page.NextCursor, "has_more": page.HasMore, "limit": page.Limit,
	})
}
