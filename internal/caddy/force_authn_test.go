//go:build unit

package caddy

import (
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

func TestMatchesForceAuthnPath_EmptyPaths(t *testing.T) {
	paths := []string{}
	if httputil.MatchesForceAuthnPath("/admin/settings", paths) {
		t.Error("empty paths should not match anything")
	}
}

func TestMatchesForceAuthnPath_ExactMatch(t *testing.T) {
	paths := []string{"/admin/settings"}
	if !httputil.MatchesForceAuthnPath("/admin/settings", paths) {
		t.Error("exact path should match")
	}
}

func TestMatchesForceAuthnPath_WildcardSuffix(t *testing.T) {
	paths := []string{"/admin/*"}

	tests := []struct {
		path  string
		match bool
	}{
		{"/admin/settings", true},
		{"/admin/users/edit", true},
		{"/admin", false}, // No trailing path
		{"/public/page", false},
	}

	for _, tc := range tests {
		if got := httputil.MatchesForceAuthnPath(tc.path, paths); got != tc.match {
			t.Errorf("httputil.MatchesForceAuthnPath(%q) = %v, want %v", tc.path, got, tc.match)
		}
	}
}

func TestMatchesForceAuthnPath_MultiplePatterns(t *testing.T) {
	paths := []string{"/admin/*", "/settings/security"}

	tests := []struct {
		path  string
		match bool
	}{
		{"/admin/settings", true},
		{"/settings/security", true},
		{"/settings/public", false},
		{"/public/page", false},
	}

	for _, tc := range tests {
		if got := httputil.MatchesForceAuthnPath(tc.path, paths); got != tc.match {
			t.Errorf("httputil.MatchesForceAuthnPath(%q) = %v, want %v", tc.path, got, tc.match)
		}
	}
}

func TestMatchesForceAuthnPath_NoMatch(t *testing.T) {
	paths := []string{"/admin/*"}
	if httputil.MatchesForceAuthnPath("/public/page", paths) {
		t.Error("non-matching path should not match")
	}
}
