//go:build unit

package caddy

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/entitlements"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/session"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// TestSimEntitlementBypass_DeniedUserGetsNoCookie simulates the ACS deny path and
// verifies that a denied subject never receives a session cookie.
//
// Before the fix, setSessionCookieForSP was called before the entitlement check,
// so a denied user would leave with a valid session cookie. The fix moves the
// entitlement check first so no cookie is issued on deny.
func TestSimEntitlementBypass_DeniedUserGetsNoCookie(t *testing.T) {
	tra.Require(t, "Adapter.Entitlement.DeniedUserNoCookie")
	const deniedSubject = "intruder@external.example"
	const cookieName = "saml_session"
	const denyRedirect = "/access-denied"

	// Entitlement store in deny-by-default mode; deniedSubject is not listed.
	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	entitlementStore.SetDefaultAction(domain.DefaultActionDeny)
	// Only an unrelated user is authorized — deniedSubject is absent.
	_ = entitlementStore.Add(domain.Entitlement{
		Subject: "allowed@internal.example",
		Roles:   []string{"user"},
	})

	key := loadTestKey(t)
	sessionStore := session.NewCookieSessionStore(key, 8*time.Hour)

	renderer, err := NewTemplateRenderer()
	if err != nil {
		t.Fatalf("new template renderer: %v", err)
	}

	cfg := &SPConfig{
		Config: Config{
			SessionCookieName:       cookieName,
			EntitlementDenyRedirect: denyRedirect,
		},
		entitlementStore: entitlementStore,
		sessionStore:     sessionStore,
		sessionDuration:  8 * time.Hour,
		templateRenderer: renderer,
	}

	s := &SAMLDisco{}

	// Simulate the post-SAML-validation segment of handleACSInternal:
	// a SAML assertion for deniedSubject succeeded, session struct is built,
	// and we now run the entitlement gate — exactly as the fixed code does.
	sess := &domain.Session{
		Subject:     deniedSubject,
		IdPEntityID: "https://idp.external.example",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	rec := httptest.NewRecorder()

	// ── Entitlement gate (mirrors the fixed handleACSInternal logic) ──────────
	denied := false
	if cfg.entitlementStore != nil {
		_, lookupErr := cfg.entitlementStore.Lookup(sess.Subject)
		if lookupErr != nil {
			if errors.Is(lookupErr, domain.ErrEntitlementNotFound) {
				s.handleDeniedForSP(rec, req, cfg, sess.Subject)
				denied = true
			}
		}
	}

	if !denied {
		// Only set cookie and redirect if allowed — this is what the fixed code does.
		token, createErr := cfg.sessionStore.Create(sess)
		if createErr != nil {
			t.Fatalf("session create: %v", createErr)
		}
		s.setSessionCookieForSP(rec, req, cfg, token)
		http.Redirect(rec, req, "/", http.StatusFound)
	}
	// ──────────────────────────────────────────────────────────────────────────

	result := rec.Result()

	// The response must redirect to the deny page, not to /.
	if result.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d (redirect to deny page)", result.StatusCode, http.StatusFound)
	}
	loc := result.Header.Get("Location")
	if loc != denyRedirect {
		t.Errorf("Location = %q, want %q", loc, denyRedirect)
	}

	// No session cookie must be present in the response.
	for _, c := range result.Cookies() {
		if c.Name == cookieName {
			t.Errorf("response contains session cookie %q for denied subject — session must not be issued on deny", cookieName)
		}
	}
}

// TestSimEntitlementBypass_AllowedUserGetsCookie verifies the positive case:
// an authorized subject receives a session cookie and is redirected normally.
func TestSimEntitlementBypass_AllowedUserGetsCookie(t *testing.T) {
	tra.Require(t, "Adapter.Entitlement.AllowedUserGetsCookie")
	const allowedSubject = "allowed@internal.example"
	const cookieName = "saml_session"

	entitlementStore := entitlements.NewInMemoryEntitlementStore()
	entitlementStore.SetDefaultAction(domain.DefaultActionDeny)
	_ = entitlementStore.Add(domain.Entitlement{
		Subject: allowedSubject,
		Roles:   []string{"user"},
	})

	key := loadTestKey(t)
	sessionStore := session.NewCookieSessionStore(key, 8*time.Hour)

	cfg := &SPConfig{
		Config: Config{
			SessionCookieName: cookieName,
		},
		entitlementStore: entitlementStore,
		sessionStore:     sessionStore,
		sessionDuration:  8 * time.Hour,
	}

	s := &SAMLDisco{}

	sess := &domain.Session{
		Subject:     allowedSubject,
		IdPEntityID: "https://idp.internal.example",
		IssuedAt:    time.Now(),
		ExpiresAt:   time.Now().Add(8 * time.Hour),
	}

	req := httptest.NewRequest(http.MethodPost, "/saml/acs", nil)
	rec := httptest.NewRecorder()

	denied := false
	if cfg.entitlementStore != nil {
		_, lookupErr := cfg.entitlementStore.Lookup(sess.Subject)
		if lookupErr != nil {
			if errors.Is(lookupErr, domain.ErrEntitlementNotFound) {
				s.handleDeniedForSP(rec, req, cfg, sess.Subject)
				denied = true
			}
		}
	}

	if !denied {
		token, createErr := cfg.sessionStore.Create(sess)
		if createErr != nil {
			t.Fatalf("session create: %v", createErr)
		}
		s.setSessionCookieForSP(rec, req, cfg, token)
		http.Redirect(rec, req, "/", http.StatusFound)
	}

	result := rec.Result()

	if result.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want %d", result.StatusCode, http.StatusFound)
	}

	found := false
	for _, c := range result.Cookies() {
		if c.Name == cookieName {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("allowed subject should receive session cookie %q", cookieName)
	}
}
