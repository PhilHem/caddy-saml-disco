//go:build unit

package discovery

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

// stubSessionStore is a closure-based test double for ports.SessionStore.
type stubSessionStore struct {
	_create func(*domain.Session) (string, error)
	_get    func(string) (*domain.Session, error)
	_delete func(string) error
}

func newStubSessionStore() *stubSessionStore {
	return &stubSessionStore{
		_create: func(*domain.Session) (string, error) { return "stub-token", nil },
		_get:    func(string) (*domain.Session, error) { return nil, ports.ErrSessionNotFound },
		_delete: func(string) error { return nil },
	}
}

func (s *stubSessionStore) Create(session *domain.Session) (string, error) { return s._create(session) }
func (s *stubSessionStore) Get(token string) (*domain.Session, error)      { return s._get(token) }
func (s *stubSessionStore) Delete(token string) error                      { return s._delete(token) }

var _ ports.SessionStore = (*stubSessionStore)(nil)

const (
	bypassEntityID = "https://idp.uni-tuebingen.de/shibboleth"
	testReturnURL  = "/app"
)

// newPasscodeHandler builds a DiscoveryHandler wired with a metadata store
// (containing the bypass IdP plus a normal one), a session store, a renderer,
// and the given guest config.
func newPasscodeHandler(t *testing.T, guestPasscode string) *DiscoveryHandler {
	t.Helper()
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{
		{EntityID: bypassEntityID, DisplayName: "Uni Tübingen", SSOURL: "https://idp.uni-tuebingen.de/sso"},
		{EntityID: "https://normal.example.org/idp", DisplayName: "Normal IdP", SSOURL: "https://normal.example.org/sso"},
	})
	return &DiscoveryHandler{
		MetadataStore: store,
		SessionStore:  newStubSessionStore(),
		Renderer:      renderer,
		Config: Config{
			GuestAccessLabel:  "Rechtsberatung",
			BypassIdPs:        []string{bypassEntityID},
			GuestPasscode:     guestPasscode,
			SessionCookieName: "saml_session",
			SessionDuration:   8 * time.Hour,
			CookieSecure:      "never",
		},
	}
}

func postSelect(t *testing.T, h *DiscoveryHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/saml/api/select", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := h.HandleSelectIdP(rec, req); err != nil {
		t.Fatalf("HandleSelectIdP returned error: %v", err)
	}
	return rec
}

func hasSessionCookie(rec *httptest.ResponseRecorder) bool {
	for _, c := range rec.Result().Cookies() {
		if c.Name == "saml_session" && c.Value != "" {
			return true
		}
	}
	return false
}

// TestSelectIdP_PasscodeGate_GuestAndBypass covers the matrix of guest/bypass
// selection against correct, wrong, and missing passcodes when one is configured.
func TestSelectIdP_PasscodeGate_GuestAndBypass(t *testing.T) {
	const passcode = "my password"

	tests := []struct {
		name           string
		entityID       string
		supplied       string
		omitPasscode   bool
		wantStatus     int
		wantSession    bool
		wantInvalidErr bool
	}{
		{name: "guest correct passcode", entityID: GuestEntityID, supplied: passcode, wantStatus: http.StatusOK, wantSession: true},
		{name: "guest wrong passcode", entityID: GuestEntityID, supplied: "nope", wantStatus: http.StatusUnauthorized, wantInvalidErr: true},
		{name: "guest missing passcode", entityID: GuestEntityID, omitPasscode: true, wantStatus: http.StatusUnauthorized, wantInvalidErr: true},
		{name: "bypass correct passcode", entityID: bypassEntityID, supplied: passcode, wantStatus: http.StatusOK, wantSession: true},
		{name: "bypass wrong passcode", entityID: bypassEntityID, supplied: "nope", wantStatus: http.StatusUnauthorized, wantInvalidErr: true},
		{name: "bypass missing passcode", entityID: bypassEntityID, omitPasscode: true, wantStatus: http.StatusUnauthorized, wantInvalidErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newPasscodeHandler(t, passcode)

			var body string
			if tc.omitPasscode {
				body = `{"entity_id":"` + tc.entityID + `","return_url":"` + testReturnURL + `"}`
			} else {
				p, _ := json.Marshal(tc.supplied)
				body = `{"entity_id":"` + tc.entityID + `","return_url":"` + testReturnURL + `","passcode":` + string(p) + `}`
			}

			rec := postSelect(t, h, body)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}

			if tc.wantInvalidErr {
				var resp map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if resp["error"] != "invalid_passcode" {
					t.Errorf("error = %q, want %q", resp["error"], "invalid_passcode")
				}
			}

			if got := hasSessionCookie(rec); got != tc.wantSession {
				t.Errorf("session cookie set = %v, want %v", got, tc.wantSession)
			}

			if tc.wantStatus == http.StatusOK {
				var resp map[string]string
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("decode body: %v", err)
				}
				if resp["redirect_url"] != testReturnURL {
					t.Errorf("redirect_url = %q, want %q", resp["redirect_url"], testReturnURL)
				}
			}
		})
	}
}

// TestSelectIdP_PerTargetPasscodes verifies that guest_access and a bypass IdP
// can carry distinct passcodes: each target accepts only its own code, and the
// other target's code is rejected.
func TestSelectIdP_PerTargetPasscodes(t *testing.T) {
	const guestCode = "guest-code-AAAA"
	const bypassCode = "bypass-code-BBBB"

	newHandler := func() *DiscoveryHandler {
		h := newPasscodeHandler(t, "") // no shared default
		h.Config.GuestPasscodes = map[string]string{
			GuestEntityID:  guestCode,
			bypassEntityID: bypassCode,
		}
		return h
	}

	tests := []struct {
		name        string
		entityID    string
		supplied    string
		wantStatus  int
		wantSession bool
	}{
		{"guest accepts its own code", GuestEntityID, guestCode, http.StatusOK, true},
		{"guest rejects the bypass code", GuestEntityID, bypassCode, http.StatusUnauthorized, false},
		{"bypass accepts its own code", bypassEntityID, bypassCode, http.StatusOK, true},
		{"bypass rejects the guest code", bypassEntityID, guestCode, http.StatusUnauthorized, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler()
			p, _ := json.Marshal(tc.supplied)
			body := `{"entity_id":"` + tc.entityID + `","return_url":"` + testReturnURL + `","passcode":` + string(p) + `}`
			rec := postSelect(t, h, body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if got := hasSessionCookie(rec); got != tc.wantSession {
				t.Errorf("session cookie = %v, want %v", got, tc.wantSession)
			}
		})
	}
}

// TestSelectIdP_PerTargetOverrideAndFallback verifies that a per-target passcode
// overrides the shared default for that target only, while a target without its
// own entry keeps using the shared default.
func TestSelectIdP_PerTargetOverrideAndFallback(t *testing.T) {
	const shared = "shared-default"
	const guestOnly = "guest-only-code"

	newHandler := func() *DiscoveryHandler {
		h := newPasscodeHandler(t, shared) // shared default for any target...
		h.Config.GuestPasscodes = map[string]string{
			GuestEntityID: guestOnly, // ...overridden for the guest entry only
		}
		return h
	}

	tests := []struct {
		name       string
		entityID   string
		supplied   string
		wantStatus int
	}{
		{"guest uses its override, not the default", GuestEntityID, guestOnly, http.StatusOK},
		{"guest rejects the shared default", GuestEntityID, shared, http.StatusUnauthorized},
		{"bypass falls back to the shared default", bypassEntityID, shared, http.StatusOK},
		{"bypass rejects the guest override", bypassEntityID, guestOnly, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newHandler()
			p, _ := json.Marshal(tc.supplied)
			body := `{"entity_id":"` + tc.entityID + `","return_url":"` + testReturnURL + `","passcode":` + string(p) + `}`
			rec := postSelect(t, h, body)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// TestSelectIdP_PerTargetGatedAndUngated verifies that gating one target does not
// gate another: with only the guest entry in the per-target map and no shared
// default, the bypass IdP stays reachable without a passcode.
func TestSelectIdP_PerTargetGatedAndUngated(t *testing.T) {
	const guestCode = "guest-code-only"

	newHandler := func() *DiscoveryHandler {
		h := newPasscodeHandler(t, "") // no shared default
		h.Config.GuestPasscodes = map[string]string{GuestEntityID: guestCode}
		return h
	}

	t.Run("guest is gated", func(t *testing.T) {
		h := newHandler()
		body := `{"entity_id":"` + GuestEntityID + `","return_url":"` + testReturnURL + `"}`
		rec := postSelect(t, h, body)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("bypass stays ungated", func(t *testing.T) {
		h := newHandler()
		body := `{"entity_id":"` + bypassEntityID + `","return_url":"` + testReturnURL + `"}`
		rec := postSelect(t, h, body)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
		}
		if !hasSessionCookie(rec) {
			t.Error("expected an ungated bypass to mint a session without a passcode")
		}
	})
}

// TestSelectIdP_NoPasscodeConfigured_UngatedBackdoors verifies that when no
// passcode is configured, guest and bypass sessions are created without one,
// preserving the original behavior.
func TestSelectIdP_NoPasscodeConfigured_UngatedBackdoors(t *testing.T) {
	tests := []struct {
		name     string
		entityID string
	}{
		{name: "guest", entityID: GuestEntityID},
		{name: "bypass", entityID: bypassEntityID},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newPasscodeHandler(t, "") // no passcode

			body := `{"entity_id":"` + tc.entityID + `","return_url":"` + testReturnURL + `"}`
			rec := postSelect(t, h, body)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
			}
			if !hasSessionCookie(rec) {
				t.Error("expected a session cookie to be set without a passcode")
			}
		})
	}
}

// TestSelectIdP_NormalIdP_UnaffectedByPasscode verifies a real SAML IdP selection
// never requires a passcode, regardless of guest_passcode configuration.
func TestSelectIdP_NormalIdP_UnaffectedByPasscode(t *testing.T) {
	for _, passcode := range []string{"", "my password"} {
		name := "no passcode configured"
		if passcode != "" {
			name = "passcode configured"
		}
		t.Run(name, func(t *testing.T) {
			h := newPasscodeHandler(t, passcode)
			// No SAMLService is wired, so a real IdP selection reaches the
			// "SAML service is not configured" branch (500) — crucially NOT a
			// 401 invalid_passcode, proving the passcode gate does not apply to
			// real IdPs.
			body := `{"entity_id":"https://normal.example.org/idp","return_url":"` + testReturnURL + `"}`
			rec := postSelect(t, h, body)

			if rec.Code == http.StatusUnauthorized {
				t.Fatalf("normal IdP selection returned 401 (passcode gate leaked onto a real IdP)")
			}
			if strings.Contains(rec.Body.String(), "invalid_passcode") {
				t.Errorf("normal IdP response contained invalid_passcode: %s", rec.Body.String())
			}
		})
	}
}

// TestDiscoveryUI_SingleBypassIdP_RendersPageWhenPasscodeConfigured verifies that
// the single-IdP auto-bypass shortcut falls back to rendering the discovery page
// (rather than silently minting a bypass session) when a passcode is configured.
func TestDiscoveryUI_SingleBypassIdP_RendersPageWhenPasscodeConfigured(t *testing.T) {
	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}
	// Exactly one IdP, and it is a bypass IdP -> the auto-bypass shortcut fires.
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{
		{EntityID: bypassEntityID, DisplayName: "Uni Tübingen", SSOURL: "https://idp.uni-tuebingen.de/sso"},
	})

	newHandler := func(passcode string) *DiscoveryHandler {
		return &DiscoveryHandler{
			MetadataStore: store,
			SessionStore:  newStubSessionStore(),
			Renderer:      renderer,
			Config: Config{
				BypassIdPs:        []string{bypassEntityID},
				GuestPasscode:     passcode,
				SessionCookieName: "saml_session",
				SessionDuration:   8 * time.Hour,
				CookieSecure:      "never",
			},
		}
	}

	t.Run("passcode configured renders page, no bypass session", func(t *testing.T) {
		h := newHandler("my password")
		req := httptest.NewRequest(http.MethodGet, "/saml/disco", nil)
		rec := httptest.NewRecorder()
		if err := h.HandleDiscoveryUI(rec, req); err != nil {
			t.Fatalf("HandleDiscoveryUI: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("Content-Type = %q, want HTML page", ct)
		}
		if hasSessionCookie(rec) {
			t.Error("a bypass session was minted by a plain page navigation despite a configured passcode")
		}
	})

	t.Run("no passcode auto-bypasses as before", func(t *testing.T) {
		h := newHandler("")
		req := httptest.NewRequest(http.MethodGet, "/saml/disco", nil)
		rec := httptest.NewRecorder()
		if err := h.HandleDiscoveryUI(rec, req); err != nil {
			t.Fatalf("HandleDiscoveryUI: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !hasSessionCookie(rec) {
			t.Error("expected the single-IdP auto-bypass to mint a session when no passcode is configured")
		}
	})
}

// TestRenderDiscoData_PasscodeRequiredFields verifies that the discovery page data
// exposes the passcode-required entity IDs only when a passcode is configured.
// It renders through a probe template (loaded from a temp dir) that prints the
// passcode fields, exercising the real renderDiscoveryHTML path end to end.
func TestRenderDiscoData_PasscodeRequiredFields(t *testing.T) {
	dir := t.TempDir()
	probe := `required={{.PasscodeRequired}};` +
		`ids=[{{range $i, $e := .PasscodeRequiredEntityIDs}}{{if $i}},{{end}}{{$e}}{{end}}]`
	if err := os.WriteFile(filepath.Join(dir, "disco.html"), []byte(probe), 0o600); err != nil {
		t.Fatalf("write probe template: %v", err)
	}
	renderer, err := NewTemplateRendererWithDir(dir)
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}

	tests := []struct {
		name     string
		passcode string
		want     string
	}{
		{
			name:     "passcode configured exposes guest + bypass ids",
			passcode: "my password",
			want:     "required=true;ids=[" + GuestEntityID + "," + bypassEntityID + "]",
		},
		{
			name:     "no passcode exposes nothing",
			passcode: "",
			want:     "required=false;ids=[]",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newPasscodeHandler(t, tc.passcode)
			h.Renderer = renderer

			req := httptest.NewRequest(http.MethodGet, "/saml/disco?return_url=/x", nil)
			// Two IdPs are present, so HandleDiscoveryUI renders the page (no
			// single-IdP shortcut) and threads DiscoData through renderDiscoveryHTML.
			rec := httptest.NewRecorder()
			if err := h.HandleDiscoveryUI(rec, req); err != nil {
				t.Fatalf("HandleDiscoveryUI: %v", err)
			}
			if got := rec.Body.String(); got != tc.want {
				t.Errorf("rendered data = %q, want %q", got, tc.want)
			}
		})
	}

	// Per-target: only the guest entry carries a passcode, so only it appears in
	// the page's passcode-required list — the ungated bypass IdP must not.
	t.Run("per-target gating lists only the gated entry", func(t *testing.T) {
		h := newPasscodeHandler(t, "") // no shared default
		h.Config.GuestPasscodes = map[string]string{GuestEntityID: "guest-only"}
		h.Renderer = renderer

		req := httptest.NewRequest(http.MethodGet, "/saml/disco?return_url=/x", nil)
		rec := httptest.NewRecorder()
		if err := h.HandleDiscoveryUI(rec, req); err != nil {
			t.Fatalf("HandleDiscoveryUI: %v", err)
		}
		want := "required=true;ids=[" + GuestEntityID + "]"
		if got := rec.Body.String(); got != want {
			t.Errorf("rendered data = %q, want %q", got, want)
		}
	})
}
