package config

import (
	"strings"
	"testing"
	"time"
)

func TestPortalConfigDefaultsAreOff(t *testing.T) {
	for _, key := range []string{"OMCPA_PORTAL_ENABLED", "OMCPA_PORTAL_REGISTRATION", "OMCPA_PORTAL_SESSION_TTL",
		"OMCPA_PORTAL_GATEWAY_URL", "OMCPA_PORTAL_SHOW_COST", "OMCPA_PORTAL_SYNC_INTERVAL"} {
		t.Setenv(key, "")
	}
	cfg, err := loadPortalConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled || cfg.Registration != PortalRegistrationOff || cfg.SessionTTL != 168*time.Hour ||
		!cfg.ShowCost || cfg.SyncInterval != time.Minute || cfg.GatewayURL != "" {
		t.Fatalf("defaults = %+v", cfg)
	}
}

func TestPortalConfigParsesAndRejects(t *testing.T) {
	t.Setenv("OMCPA_PORTAL_ENABLED", "true")
	t.Setenv("OMCPA_PORTAL_REGISTRATION", "INVITE")
	t.Setenv("OMCPA_PORTAL_SESSION_TTL", "12h")
	t.Setenv("OMCPA_PORTAL_GATEWAY_URL", "https://api.example.test/v1")
	t.Setenv("OMCPA_PORTAL_SHOW_COST", "false")
	t.Setenv("OMCPA_PORTAL_SYNC_INTERVAL", "30s")
	cfg, err := loadPortalConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.Registration != PortalRegistrationInvite || cfg.SessionTTL != 12*time.Hour ||
		cfg.ShowCost || cfg.SyncInterval != 30*time.Second || cfg.GatewayURL != "https://api.example.test/v1" {
		t.Fatalf("parsed = %+v", cfg)
	}
	for key, value := range map[string]string{
		"OMCPA_PORTAL_REGISTRATION":  "public",
		"OMCPA_PORTAL_SESSION_TTL":   "1m",
		"OMCPA_PORTAL_SYNC_INTERVAL": "1s",
		"OMCPA_PORTAL_GATEWAY_URL":   "https://user:pass@api.example.test",
	} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, value)
			if _, err := loadPortalConfig(); err == nil || !strings.Contains(err.Error(), key) {
				t.Fatalf("%s=%q accepted: %v", key, value, err)
			}
		})
	}
}
