//go:build unit

package discovery

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

type stubAuthStarter struct{}

func (stubAuthStarter) StartAuthWithOptions(_ *domain.IdPInfo, _ *url.URL, _ string, _ *domain.AuthnOptions) (*url.URL, error) {
	return url.Parse("https://idp.example.edu/sso?SAMLRequest=test")
}

func TestSelectIdPLogsAggregateSafeSAMLStart(t *testing.T) {
	tra.Require(t, "Adapter.SAMLOrgEntryLogging")

	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)
	entityID := "https://idp.example.edu/idp/shibboleth"
	h := &DiscoveryHandler{
		MetadataStore: metadata.NewInMemoryMetadataStore([]domain.IdPInfo{
			{
				EntityID:              entityID,
				DisplayName:           "Example University",
				RegistrationAuthority: "https://federation.example.org",
				SSOURL:                "https://idp.example.edu/sso",
			},
		}),
		SAMLService: stubAuthStarter{},
		Logger:      logger,
		Config: Config{
			ForceAuthnPaths: []string{"/secure/*"},
		},
	}

	body := `{"entity_id":"` + entityID + `","return_url":"/secure/page","remember":true}`
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if err := h.HandleSelectIdP(rec, req); err != nil {
		t.Fatalf("HandleSelectIdP: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}

	selectedEntries := logs.FilterMessage("saml idp selected").All()
	if len(selectedEntries) != 1 {
		t.Fatalf("saml idp selected logs = %d, want 1", len(selectedEntries))
	}
	selectedFields := selectedEntries[0].ContextMap()
	t.Logf("observed aggregate selected log fields: %#v", selectedFields)
	assertField(t, selectedFields, "event", "saml_disco_idp_selected")
	assertField(t, selectedFields, "auth_flow", "saml")
	assertField(t, selectedFields, "idp_entity_id", entityID)
	assertField(t, selectedFields, "idp_display_name", "Example University")
	assertField(t, selectedFields, "idp_registration_authority", "https://federation.example.org")
	assertField(t, selectedFields, "entry_point", "api_select")
	assertField(t, selectedFields, "remember_idp", true)
	assertAbsentField(t, selectedFields, "subject")

	entries := logs.FilterMessage("saml login started").All()
	if len(entries) != 1 {
		t.Fatalf("saml login started logs = %d, want 1", len(entries))
	}
	fields := entries[0].ContextMap()
	t.Logf("observed aggregate log fields: %#v", fields)
	assertField(t, fields, "event", "saml_disco_login_started")
	assertField(t, fields, "auth_flow", "saml")
	assertField(t, fields, "idp_entity_id", entityID)
	assertField(t, fields, "idp_display_name", "Example University")
	assertField(t, fields, "idp_registration_authority", "https://federation.example.org")
	assertField(t, fields, "entry_point", "api_select")
	assertField(t, fields, "force_authn", true)
	assertField(t, fields, "remember_idp", true)
	assertAbsentField(t, fields, "subject")
}

func TestSelectIdPLogsAggregateSafeNoAuthSessionEvents(t *testing.T) {
	tra.Require(t, "Adapter.SAMLOrgEntryLogging")

	core, logs := observer.New(zap.InfoLevel)
	h := newPasscodeHandler(t, "")
	h.Logger = zap.New(core)
	h.Config.SessionDuration = time.Hour

	for _, entityID := range []string{bypassEntityID, GuestEntityID} {
		body := `{"entity_id":"` + entityID + `","return_url":"` + testReturnURL + `"}`
		rec := postSelect(t, h, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("entity %s status = %d, want %d (body: %s)", entityID, rec.Code, http.StatusOK, rec.Body.String())
		}
	}

	entries := logs.FilterMessage("saml disco session created").All()
	if len(entries) != 2 {
		t.Fatalf("session-created logs = %d, want 2", len(entries))
	}
	byFlow := map[string]map[string]interface{}{}
	for _, entry := range entries {
		fields := entry.ContextMap()
		t.Logf("observed aggregate session log fields: %#v", fields)
		flow, ok := fields["auth_flow"].(string)
		if !ok || flow == "" {
			t.Fatalf("auth_flow field missing or non-string: %#v", fields["auth_flow"])
		}
		byFlow[flow] = fields
		assertField(t, fields, "event", "saml_disco_session_created")
		assertAbsentField(t, fields, "subject")
	}

	assertField(t, byFlow["bypass"], "idp_entity_id", bypassEntityID)
	assertField(t, byFlow["bypass"], "idp_display_name", "Uni Tübingen")
	assertField(t, byFlow["guest"], "idp_entity_id", GuestEntityID)
	assertField(t, byFlow["guest"], "idp_display_name", "Rechtsberatung")
}

func assertField(t *testing.T, fields map[string]interface{}, key string, want interface{}) {
	t.Helper()
	if fields == nil {
		t.Fatalf("fields map is nil while checking %s", key)
	}
	if got := fields[key]; got != want {
		t.Fatalf("field %s = %#v, want %#v (all fields: %#v)", key, got, want, fields)
	}
}

func assertAbsentField(t *testing.T, fields map[string]interface{}, key string) {
	t.Helper()
	if _, ok := fields[key]; ok {
		t.Fatalf("field %s should be absent (all fields: %#v)", key, fields)
	}
}
