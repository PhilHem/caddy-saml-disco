//go:build unit

package httputil

import (
	"net/url"
	"strings"
	"testing"
)

func TestValidateRelayState(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		// Valid relative paths
		{"empty", "", "/"},
		{"root", "/", "/"},
		{"simple path", "/dashboard", "/dashboard"},
		{"path with query", "/page?foo=bar", "/page?foo=bar"},
		{"path with fragment", "/page#section", "/page#section"},
		{"nested path", "/app/settings/profile", "/app/settings/profile"},

		// Absolute URLs - should be rejected (open redirect)
		{"absolute http", "http://evil.com", "/"},
		{"absolute https", "https://evil.com/path", "/"},
		{"absolute with port", "https://evil.com:8080/path", "/"},

		// Protocol-relative URLs - should be rejected
		{"protocol relative", "//evil.com", "/"},
		{"protocol relative with path", "//evil.com/path", "/"},

		// Dangerous schemes - should be rejected
		{"javascript scheme", "javascript:alert(1)", "/"},
		{"data scheme", "data:text/html,<script>alert(1)</script>", "/"},
		{"vbscript scheme", "vbscript:msgbox(1)", "/"},

		// Edge cases
		{"backslash escape", "\\\\evil.com", "/"},
		{"encoded slashes", "%2f%2fevil.com", "/"},
		{"whitespace prefix becomes valid", " /valid", "/valid"},
		{"tab prefix becomes valid", "\t/valid", "/valid"},
		{"only whitespace", "   ", "/"},
		{"newline in path", "/path\nHeader: injection", "/"},

		// Double-encoding bypass attempts - should be rejected
		{"double encoded protocol relative", "/%2f%2fevil.com", "/"},
		{"triple encoded protocol relative", "/%252f%252fevil.com", "/"},
		{"double encoded with path", "/%2f%2fevil.com/path", "/"},
		{"mixed encoding bypass", "/%2F%2Fevil.com", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

func TestValidateRelayState_DoubleEncodedBypass(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		{"double encoded //", "/%2f%2fevil.com", "/"},
		{"triple encoded //", "/%252f%252fevil.com", "/"},
		{"double encoded with path", "/%2f%2fevil.com/path", "/"},
		{"mixed case encoding", "/%2F%2Fevil.com", "/"},
		{"quadruple encoded", "/%25252f%25252fevil.com", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

func TestValidateRelayState_EncodedProtocolMarker(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		{"http: encoded", "/path?redirect=http%3A//evil.com", "/"},
		{"https: encoded", "/path?redirect=https%3A//evil.com", "/"},
		{"javascript: encoded", "javascript%3Aalert(1)", "/"},
		{"data: encoded", "data%3Atext/html,evil", "/"},
		{"encoded colon in path", "/path%3A//evil.com", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

func TestValidateRelayState_MixedEncodingBypass(t *testing.T) {
	tests := []struct {
		name       string
		relayState string
		want       string
	}{
		{"encoded slash then literal", "/%2f/evil.com", "/"},
		{"literal then encoded", "//%2fevil.com", "/"},
		{"mixed with uppercase", "/%2F/evil.com", "/"},
		{"partial encoding", "/path/%2f%2fevil.com", "/"},
		{"nested encoding layers", "/%252F%252Fevil.com", "/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateRelayState(tc.relayState)
			if got != tc.want {
				t.Errorf("ValidateRelayState(%q) = %q, want %q", tc.relayState, got, tc.want)
			}
		})
	}
}

func TestMatchesForceAuthnPath_EmptyPaths(t *testing.T) {
	paths := []string{}
	if MatchesForceAuthnPath("/admin/settings", paths) {
		t.Error("empty paths should not match anything")
	}
}

func TestMatchesForceAuthnPath_ExactMatch(t *testing.T) {
	paths := []string{"/admin/settings"}
	if !MatchesForceAuthnPath("/admin/settings", paths) {
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
		{"/admin", false},
		{"/public/page", false},
	}

	for _, tc := range tests {
		if got := MatchesForceAuthnPath(tc.path, paths); got != tc.match {
			t.Errorf("MatchesForceAuthnPath(%q) = %v, want %v", tc.path, got, tc.match)
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
		if got := MatchesForceAuthnPath(tc.path, paths); got != tc.match {
			t.Errorf("MatchesForceAuthnPath(%q) = %v, want %v", tc.path, got, tc.match)
		}
	}
}

func TestMatchesForceAuthnPath_NoMatch(t *testing.T) {
	paths := []string{"/admin/*"}
	if MatchesForceAuthnPath("/public/page", paths) {
		t.Error("non-matching path should not match")
	}
}

// FuzzValidateRelayState_Invariants is a property test that validates all security invariants.
func FuzzValidateRelayState_Invariants(f *testing.F) {
	seeds := []string{
		"", "/", "/dashboard", "/page?foo=bar",
		"http://evil.com", "//evil.com",
		"javascript:alert(1)",
		"%2f%2fevil.com",
		"/path\r\nHeader: injection",
		"/%252f%252fevil.com",
		"/path?redirect=http%3A//evil.com",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := ValidateRelayState(input)

		if result == "" {
			t.Errorf("ValidateRelayState(%q) returned empty string", input)
		}

		if !strings.HasPrefix(result, "/") {
			t.Errorf("ValidateRelayState(%q) = %q, does not start with /", input, result)
		}

		if strings.HasPrefix(result, "//") {
			t.Errorf("ValidateRelayState(%q) = %q, starts with // (protocol-relative)", input, result)
		}

		parsed, err := url.Parse(result)
		if err != nil {
			t.Errorf("ValidateRelayState(%q) = %q, failed to parse: %v", input, result, err)
		} else {
			if parsed.Scheme != "" {
				t.Errorf("ValidateRelayState(%q) = %q, has scheme: %q", input, result, parsed.Scheme)
			}
			if parsed.Host != "" {
				t.Errorf("ValidateRelayState(%q) = %q, has host: %q", input, result, parsed.Host)
			}
		}

		if strings.ContainsAny(result, "\r\n") {
			t.Errorf("ValidateRelayState(%q) = %q, contains CR/LF", input, result)
		}

		decoded := result
		for i := 0; i < 10; i++ {
			newDecoded, err := url.QueryUnescape(decoded)
			if err != nil || newDecoded == decoded {
				break
			}
			decoded = newDecoded
		}

		if strings.Contains(decoded, "://") {
			t.Errorf("ValidateRelayState(%q) = %q, decoded contains protocol marker: %q", input, result, decoded)
		}
		if strings.HasPrefix(decoded, "//") {
			t.Errorf("ValidateRelayState(%q) = %q, decoded starts with //: %q", input, result, decoded)
		}
	})
}
