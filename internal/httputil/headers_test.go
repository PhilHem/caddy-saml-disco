//go:build unit

package httputil

import (
	"net/http"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"go.uber.org/zap"
)

func TestDeleteHeaderCaseInsensitive(t *testing.T) {
	r := &http.Request{Header: http.Header{
		"X-User-Email": []string{"user@example.com"},
		"X-Other":      []string{"value"},
	}}

	DeleteHeaderCaseInsensitive(r, "X-User-Email")

	if r.Header.Get("X-User-Email") != "" {
		t.Error("expected X-User-Email to be deleted")
	}
	if r.Header.Get("X-Other") != "value" {
		t.Error("expected X-Other to be preserved")
	}
}

func TestRestoreHeaderState(t *testing.T) {
	r := &http.Request{Header: http.Header{
		"X-User-Email": []string{"new@example.com"},
	}}

	original := map[string][]string{
		"X-User-Email": {"original@example.com"},
	}

	RestoreHeaderState(r, original)

	if got := r.Header.Get("X-User-Email"); got != "original@example.com" {
		t.Errorf("X-User-Email = %q, want original@example.com", got)
	}
}

func TestSaveHeaderState(t *testing.T) {
	r := &http.Request{Header: http.Header{
		"X-User-Email": []string{"user@example.com"},
	}}

	mappings := []domain.AttributeMapping{
		{SAMLAttribute: "email", HeaderName: "X-User-Email"},
	}

	state := SaveHeaderState(r, mappings, "")
	if state["X-User-Email"] == nil {
		t.Error("expected X-User-Email to be saved in state")
	}
	if state["X-User-Email"][0] != "user@example.com" {
		t.Errorf("saved value = %q, want user@example.com", state["X-User-Email"][0])
	}
}

func TestApplyAttributeHeadersCore_BasicMapping(t *testing.T) {
	req := &http.Request{Header: http.Header{}}
	session := &domain.Session{
		Subject: "user@example.com",
		Attributes: map[string]string{
			"email":       "user@example.com",
			"displayName": "Test User",
		},
	}

	cfg := HeaderConfig{
		AttributeHeaders: []domain.AttributeMapping{
			{SAMLAttribute: "email", HeaderName: "X-User-Email"},
			{SAMLAttribute: "displayName", HeaderName: "X-User-Name"},
		},
		HeaderPrefix: "",
		StripHeaders: false,
	}

	ApplyAttributeHeadersCore(req, session, cfg, zap.NewNop())

	if got := req.Header.Get("X-User-Email"); got != "user@example.com" {
		t.Errorf("X-User-Email = %q, want user@example.com", got)
	}
	if got := req.Header.Get("X-User-Name"); got != "Test User" {
		t.Errorf("X-User-Name = %q, want Test User", got)
	}
}
