//go:build unit

package authentication

import (
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

func TestLogAuthenticationSuccessLogsAggregateSafeSessionEvent(t *testing.T) {
	tra.Require(t, "Adapter.SAMLOrgEntryLogging")

	core, logs := observer.New(zap.InfoLevel)
	h := &AuthHandler{Logger: zap.New(core)}
	idp := &domain.IdPInfo{
		EntityID:              "https://idp.example.edu/idp/shibboleth",
		DisplayName:           "Example University",
		RegistrationAuthority: "https://federation.example.org",
	}

	h.logAuthenticationSuccess(idp, 37*time.Millisecond)

	entries := logs.FilterMessage("saml authentication successful").All()
	if len(entries) != 1 {
		t.Fatalf("saml authentication successful logs = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	t.Logf("observed aggregate session log fields: %#v", fields)
	assertAuthField(t, fields, "event", "saml_disco_session_created")
	assertAuthField(t, fields, "auth_flow", "saml")
	assertAuthField(t, fields, "idp_entity_id", "https://idp.example.edu/idp/shibboleth")
	assertAuthField(t, fields, "idp_display_name", "Example University")
	assertAuthField(t, fields, "idp_registration_authority", "https://federation.example.org")
	assertAuthAbsentField(t, fields, "subject")
}

func assertAuthField(t *testing.T, fields map[string]interface{}, key string, want interface{}) {
	t.Helper()
	if got := fields[key]; got != want {
		t.Fatalf("field %s = %#v, want %#v (all fields: %#v)", key, got, want, fields)
	}
}

func assertAuthAbsentField(t *testing.T, fields map[string]interface{}, key string) {
	t.Helper()
	if _, ok := fields[key]; ok {
		t.Fatalf("field %s should be absent (all fields: %#v)", key, fields)
	}
}
