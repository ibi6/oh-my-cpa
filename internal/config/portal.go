package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Portal registration modes (ADR 0105).
const (
	// PortalRegistrationOff: only the operator creates accounts.
	PortalRegistrationOff = "off"
	// PortalRegistrationInvite: anyone holding an operator-issued invite code.
	PortalRegistrationInvite = "invite"
	// PortalRegistrationOpen: anyone who reaches the sign-up form.
	PortalRegistrationOpen = "open"
)

// PortalConfig configures the customer portal: customer accounts, their own
// gateway keys and their own usage (ADR 0105).
type PortalConfig struct {
	// Enabled turns the customer-facing surface and the CPA key synchronisation
	// on (OMCPA_PORTAL_ENABLED, default false). Off, the portal routes answer
	// "not found" to customers and nothing is written to CPA on their behalf;
	// the operator's account pages still work so accounts can be prepared.
	Enabled bool
	// Registration is off, invite or open (OMCPA_PORTAL_REGISTRATION, default off).
	Registration string
	// SessionTTL is how long a customer sign-in lasts (OMCPA_PORTAL_SESSION_TTL,
	// default 168h).
	SessionTTL time.Duration
	// GatewayURL is the base URL customers are told to call
	// (OMCPA_PORTAL_GATEWAY_URL). It is display text only; empty hides it.
	GatewayURL string
	// ShowCost shows customers the console's cost estimate of their requests
	// (OMCPA_PORTAL_SHOW_COST, default true).
	ShowCost bool
	// SyncInterval is how often the key reconciler compares the portal's keys
	// with CPA's access.api-keys (OMCPA_PORTAL_SYNC_INTERVAL, default 1m).
	SyncInterval time.Duration
}

func loadPortalConfig() (PortalConfig, error) {
	enabled, err := parseBoolEnv("OMCPA_PORTAL_ENABLED", false)
	if err != nil {
		return PortalConfig{}, err
	}
	showCost, err := parseBoolEnv("OMCPA_PORTAL_SHOW_COST", true)
	if err != nil {
		return PortalConfig{}, err
	}
	registration := strings.ToLower(strings.TrimSpace(envOr("OMCPA_PORTAL_REGISTRATION", PortalRegistrationOff)))
	switch registration {
	case PortalRegistrationOff, PortalRegistrationInvite, PortalRegistrationOpen:
	default:
		return PortalConfig{}, fmt.Errorf("OMCPA_PORTAL_REGISTRATION must be off, invite or open, got %q", registration)
	}
	ttl := 7 * 24 * time.Hour
	if raw := strings.TrimSpace(os.Getenv("OMCPA_PORTAL_SESSION_TTL")); raw != "" {
		parsed, parseErr := time.ParseDuration(raw)
		if parseErr != nil || parsed < 5*time.Minute || parsed > 90*24*time.Hour {
			return PortalConfig{}, fmt.Errorf("OMCPA_PORTAL_SESSION_TTL must be a duration between 5m and 2160h: %q", raw)
		}
		ttl = parsed
	}
	interval := time.Minute
	if raw := strings.TrimSpace(os.Getenv("OMCPA_PORTAL_SYNC_INTERVAL")); raw != "" {
		parsed, parseErr := time.ParseDuration(raw)
		if parseErr != nil || parsed < 10*time.Second {
			return PortalConfig{}, fmt.Errorf("OMCPA_PORTAL_SYNC_INTERVAL must be a duration of at least 10s: %q", raw)
		}
		interval = parsed
	}
	gatewayURL := strings.TrimRight(strings.TrimSpace(os.Getenv("OMCPA_PORTAL_GATEWAY_URL")), "/")
	if gatewayURL != "" {
		parsed, parseErr := url.Parse(gatewayURL)
		if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
			return PortalConfig{}, fmt.Errorf("OMCPA_PORTAL_GATEWAY_URL must be an http(s) URL without credentials: %q", gatewayURL)
		}
	}
	return PortalConfig{
		Enabled:      enabled,
		Registration: registration,
		SessionTTL:   ttl,
		GatewayURL:   gatewayURL,
		ShowCost:     showCost,
		SyncInterval: interval,
	}, nil
}
