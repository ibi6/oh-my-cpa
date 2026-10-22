package api

import (
	"database/sql"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/oh-my-cpa/oh-my-cpa/internal/portal"
	"github.com/oh-my-cpa/oh-my-cpa/internal/repository"
)

// The operator's side of the customer portal (ADR 0105). Every route here sits
// inside /api/v1, behind the operator session; nothing a customer holds opens it.

// PortalAdminUserDTO is an account row on the operator's users page.
type PortalAdminUserDTO struct {
	PortalUserDTO
	Origin       string   `json:"origin"`
	Note         string   `json:"note"`
	UpdatedAtMS  int64    `json:"updated_at_ms"`
	ActiveKeys   int      `json:"active_keys"`
	TotalKeys    int      `json:"total_keys"`
	Requests     int64    `json:"requests"`
	TotalTokens  int64    `json:"total_tokens"`
	CostUSD      *float64 `json:"cost_usd,omitempty"`
	LastUsedAtMS *int64   `json:"last_used_at_ms,omitempty"`
}

func portalAdminUserDTO(user repository.PortalUser) PortalAdminUserDTO {
	return PortalAdminUserDTO{
		PortalUserDTO: portalUserDTO(user), Origin: user.Origin, Note: user.Note, UpdatedAtMS: user.UpdatedAtMS,
	}
}

// PortalAdminKeyDTO adds the sync detail only the operator needs.
type PortalAdminKeyDTO struct {
	PortalKeyDTO
	UserID     int64  `json:"user_id"`
	SyncError  string `json:"sync_error,omitempty"`
	SyncedAtMS *int64 `json:"synced_at_ms,omitempty"`
}

// PortalInviteDTO is an invite without its code hash.
type PortalInviteDTO struct {
	ID          int64  `json:"id"`
	CodePrefix  string `json:"code_prefix"`
	Note        string `json:"note"`
	MaxUses     int    `json:"max_uses"`
	UsedCount   int    `json:"used_count"`
	ExpiresAtMS *int64 `json:"expires_at_ms,omitempty"`
	RevokedAtMS *int64 `json:"revoked_at_ms,omitempty"`
	CreatedAtMS int64  `json:"created_at_ms"`
}

func portalInviteDTO(invite repository.PortalInvite) PortalInviteDTO {
	return PortalInviteDTO{
		ID: invite.ID, CodePrefix: invite.CodePrefix, Note: invite.Note, MaxUses: invite.MaxUses,
		UsedCount: invite.UsedCount, ExpiresAtMS: invite.ExpiresAtMS, RevokedAtMS: invite.RevokedAtMS,
		CreatedAtMS: invite.CreatedAtMS,
	}
}

func (h *Handler) requirePortalAdminEnabled(writer http.ResponseWriter) bool {
	if !h.cfg.Portal.Enabled || h.cfg.IsDemoMode {
		writeJSON(writer, http.StatusConflict, map[string]string{"error": "portal_disabled", "code": "portal_disabled"})
		return false
	}
	return true
}

func (h *Handler) adminPortalStatus(writer http.ResponseWriter, request *http.Request) {
	cfg := h.cfg.Portal
	payload := map[string]any{
		"enabled":       cfg.Enabled && !h.cfg.IsDemoMode,
		"registration":  cfg.Registration,
		"gateway_url":   cfg.GatewayURL,
		"show_cost":     cfg.ShowCost,
		"session_ttl_s": int64(cfg.SessionTTL / time.Second),
		"sync_s":        int64(cfg.SyncInterval / time.Second),
		"portal_path":   h.cfg.BasePath + "/portal",
	}
	if users, err := h.repo.ListPortalUsers(request.Context()); err == nil {
		payload["users"] = len(users)
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (h *Handler) adminListPortalUsers(writer http.ResponseWriter, request *http.Request) {
	users, err := h.repo.ListPortalUsers(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	items := make([]PortalAdminUserDTO, 0, len(users))
	for _, user := range users {
		item := portalAdminUserDTO(user.PortalUser)
		item.ActiveKeys, item.TotalKeys = user.ActiveKeys, user.TotalKeys
		item.Requests, item.TotalTokens, item.LastUsedAtMS = user.Requests, user.TotalTokens, user.LastUsedAtMS
		cost := float64(user.CostNanos) / 1e9
		item.CostUSD = &cost
		items = append(items, item)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"users": items})
}

type adminCreatePortalUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Note        string `json:"note"`
	MaxKeys     *int   `json:"max_keys"`
}

func (h *Handler) adminCreatePortalUser(writer http.ResponseWriter, request *http.Request) {
	if !h.requirePortalAdminEnabled(writer) {
		return
	}
	var payload adminCreatePortalUserRequest
	if err := decodeManagementJSON(writer, request, 16*1024, &payload); err != nil {
		return
	}
	details := map[string]any{"username": payload.Username}
	if err := h.recordAudit(request, "portal.user.create", "portal_user", payload.Username, "attempt", details); err != nil {
		writeAuditFailure(writer, "audit log failure; account creation aborted")
		return
	}
	user, err := h.portalService().CreateUser(request.Context(), portal.NewUser{
		Username: payload.Username, Password: payload.Password, DisplayName: payload.DisplayName,
		Note: payload.Note, MaxKeys: payload.MaxKeys, Origin: "admin",
	})
	if err != nil {
		_ = h.recordAudit(request, "portal.user.create", "portal_user", payload.Username, "failure", mergeDetails(details, map[string]any{"error": err.Error()}))
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.user.create", "portal_user", strconv.FormatInt(user.ID, 10), "success", details)
	writeJSON(writer, http.StatusCreated, map[string]any{"user": portalAdminUserDTO(user)})
}

type adminUpdatePortalUserRequest struct {
	DisplayName *string `json:"display_name"`
	Status      *string `json:"status"`
	Note        *string `json:"note"`
	MaxKeys     *int    `json:"max_keys"`
	Password    *string `json:"password"`
}

func (h *Handler) adminUpdatePortalUser(writer http.ResponseWriter, request *http.Request) {
	if !h.requirePortalAdminEnabled(writer) {
		return
	}
	id, ok := portalIDParam(request)
	if !ok {
		h.writePortalError(writer, portal.ErrNotFound)
		return
	}
	var payload adminUpdatePortalUserRequest
	if err := decodeManagementJSON(writer, request, 16*1024, &payload); err != nil {
		return
	}
	target := strconv.FormatInt(id, 10)
	// The audit names which fields changed, never the new password.
	fields := []string{}
	for name, set := range map[string]bool{
		"display_name": payload.DisplayName != nil, "status": payload.Status != nil, "note": payload.Note != nil,
		"max_keys": payload.MaxKeys != nil, "password": payload.Password != nil,
	} {
		if set {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	details := map[string]any{"fields": fields}
	if payload.Status != nil {
		details["status"] = *payload.Status
	}
	if err := h.recordAudit(request, "portal.user.update", "portal_user", target, "attempt", details); err != nil {
		writeAuditFailure(writer, "audit log failure; account update aborted")
		return
	}
	user, err := h.portalService().UpdateUser(request.Context(), id, portal.UserPatch{
		DisplayName: payload.DisplayName, Status: payload.Status, Note: payload.Note,
		MaxKeys: payload.MaxKeys, Password: payload.Password,
	})
	if err != nil {
		_ = h.recordAudit(request, "portal.user.update", "portal_user", target, "failure", mergeDetails(details, map[string]any{"error": err.Error()}))
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.user.update", "portal_user", target, "success", details)
	writeJSON(writer, http.StatusOK, map[string]any{"user": portalAdminUserDTO(user)})
}

func (h *Handler) adminPortalUser(writer http.ResponseWriter, request *http.Request) (repository.PortalUser, bool) {
	id, ok := portalIDParam(request)
	if !ok {
		h.writePortalError(writer, portal.ErrNotFound)
		return repository.PortalUser{}, false
	}
	user, err := h.repo.GetPortalUser(request.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, repository.ErrNotFound) {
			h.writePortalError(writer, portal.ErrNotFound)
		} else {
			writeInternalError(writer, err)
		}
		return repository.PortalUser{}, false
	}
	return user, true
}

func (h *Handler) adminListPortalUserKeys(writer http.ResponseWriter, request *http.Request) {
	user, ok := h.adminPortalUser(writer, request)
	if !ok {
		return
	}
	keys, err := h.repo.ListPortalKeys(request.Context(), user.ID)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	nowMS := time.Now().UnixMilli()
	items := make([]PortalAdminKeyDTO, 0, len(keys))
	for _, key := range keys {
		items = append(items, PortalAdminKeyDTO{
			PortalKeyDTO: portalKeyDTO(key, nowMS), UserID: key.UserID, SyncError: key.SyncError, SyncedAtMS: key.SyncedAtMS,
		})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"keys": items})
}

func (h *Handler) adminPortalUserUsage(writer http.ResponseWriter, request *http.Request) {
	user, ok := h.adminPortalUser(writer, request)
	if !ok {
		return
	}
	report, err := h.portalUsageReport(request.Context(), user.ID, portalDaysParam(request), true)
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, report)
}

func (h *Handler) adminRevokePortalKey(writer http.ResponseWriter, request *http.Request) {
	if !h.requirePortalAdminEnabled(writer) {
		return
	}
	id, ok := portalIDParam(request)
	if !ok {
		h.writePortalError(writer, portal.ErrNotFound)
		return
	}
	target := strconv.FormatInt(id, 10)
	details := map[string]any{"actor": "operator"}
	if err := h.recordAudit(request, "portal.key.revoke", "portal_key", target, "attempt", details); err != nil {
		writeAuditFailure(writer, "audit log failure; key revocation aborted")
		return
	}
	key, err := h.portalService().RevokeKey(request.Context(), id, 0)
	if err != nil {
		_ = h.recordAudit(request, "portal.key.revoke", "portal_key", target, "failure", details)
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.key.revoke", "portal_key", target, "success", mergeDetails(details, map[string]any{"user_id": key.UserID}))
	writeJSON(writer, http.StatusOK, map[string]any{"key": portalKeyDTO(key, time.Now().UnixMilli())})
}

func (h *Handler) adminListPortalInvites(writer http.ResponseWriter, request *http.Request) {
	invites, err := h.repo.ListPortalInvites(request.Context())
	if err != nil {
		writeInternalError(writer, err)
		return
	}
	items := make([]PortalInviteDTO, 0, len(invites))
	for _, invite := range invites {
		items = append(items, portalInviteDTO(invite))
	}
	writeJSON(writer, http.StatusOK, map[string]any{"invites": items})
}

type adminCreatePortalInviteRequest struct {
	MaxUses     int    `json:"max_uses"`
	ExpiresAtMS *int64 `json:"expires_at_ms"`
	Note        string `json:"note"`
}

func (h *Handler) adminCreatePortalInvite(writer http.ResponseWriter, request *http.Request) {
	if !h.requirePortalAdminEnabled(writer) {
		return
	}
	var payload adminCreatePortalInviteRequest
	if err := decodeManagementJSON(writer, request, 8*1024, &payload); err != nil {
		return
	}
	details := map[string]any{"max_uses": payload.MaxUses}
	if err := h.recordAudit(request, "portal.invite.create", "portal_invite", "", "attempt", details); err != nil {
		writeAuditFailure(writer, "audit log failure; invite creation aborted")
		return
	}
	invite, code, err := h.portalService().CreateInvite(request.Context(), portal.NewInvite{
		MaxUses: payload.MaxUses, ExpiresAtMS: payload.ExpiresAtMS, Note: payload.Note,
	})
	if err != nil {
		_ = h.recordAudit(request, "portal.invite.create", "portal_invite", "", "failure", mergeDetails(details, map[string]any{"error": err.Error()}))
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.invite.create", "portal_invite", strconv.FormatInt(invite.ID, 10), "success",
		mergeDetails(details, map[string]any{"code_prefix": invite.CodePrefix}))
	writer.Header().Set("Cache-Control", "no-store")
	writeJSON(writer, http.StatusCreated, map[string]any{"invite": portalInviteDTO(invite), "code": code})
}

func (h *Handler) adminRevokePortalInvite(writer http.ResponseWriter, request *http.Request) {
	id, ok := portalIDParam(request)
	if !ok {
		h.writePortalError(writer, portal.ErrNotFound)
		return
	}
	target := strconv.FormatInt(id, 10)
	if err := h.recordAudit(request, "portal.invite.revoke", "portal_invite", target, "attempt", nil); err != nil {
		writeAuditFailure(writer, "audit log failure; invite revocation aborted")
		return
	}
	if err := h.repo.RevokePortalInvite(request.Context(), id, time.Now().UnixMilli()); err != nil {
		_ = h.recordAudit(request, "portal.invite.revoke", "portal_invite", target, "failure", nil)
		if errors.Is(err, repository.ErrNotFound) {
			h.writePortalError(writer, portal.ErrNotFound)
			return
		}
		writeInternalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.invite.revoke", "portal_invite", target, "success", nil)
	writeJSON(writer, http.StatusOK, map[string]any{"status": "revoked"})
}

func (h *Handler) adminPortalSync(writer http.ResponseWriter, request *http.Request) {
	if !h.requirePortalAdminEnabled(writer) {
		return
	}
	if err := h.recordAudit(request, "portal.sync", "portal", "keys", "attempt", nil); err != nil {
		writeAuditFailure(writer, "audit log failure; key sync aborted")
		return
	}
	report, err := h.portalService().Reconcile(request.Context())
	if err != nil {
		_ = h.recordAudit(request, "portal.sync", "portal", "keys", "failure", map[string]any{"error": err.Error()})
		h.writePortalError(writer, err)
		return
	}
	_ = h.recordAudit(request, "portal.sync", "portal", "keys", "success", map[string]any{
		"checked": report.Checked, "synced": report.Synced, "removed": report.Removed,
		"missing": report.Missing, "failed": report.Failed,
	})
	writeJSON(writer, http.StatusOK, report)
}
