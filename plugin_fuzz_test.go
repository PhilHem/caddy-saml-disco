//go:build go1.18

package caddysamldisco

import (
	"net/url"
	"strings"
	"testing"
)

// fuzzRelayStateSeeds returns seed corpus entries for relay state fuzzing.
// Minimal set covers the key attack categories.
func fuzzRelayStateSeeds() []string {
	return []string{
		// Valid paths
		"", "/", "/dashboard", "/page?foo=bar",
		// Open redirect attacks
		"http://evil.com", "//evil.com",
		// Dangerous schemes
		"javascript:alert(1)",
		// Encoding bypasses
		"%2f%2fevil.com",
		// Header injection
		"/path\r\nHeader: injection",
	}
}

// fuzzRelayStateSeedsExtended returns the full seed corpus for CI.
func fuzzRelayStateSeedsExtended() []string {
	return []string{
		// Valid relative paths
		"", "/", "/dashboard", "/page?foo=bar", "/page#section",
		"/app/settings/profile", "/path/with spaces", "/unicode/日本語",

		// Attack patterns (open redirect)
		"http://evil.com", "https://evil.com/path", "https://evil.com:8080/path",
		"//evil.com", "//evil.com/path", "///evil.com",

		// Dangerous schemes
		"javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
		"vbscript:msgbox(1)", "file:///etc/passwd", "ftp://evil.com",

		// URL encoding bypasses
		"%2f%2fevil.com", "%2F%2Fevil.com", "/%2fevil.com", "/%2Fevil.com",
		"%252f%252fevil.com", "/path%00//evil.com",

		// Mixed slashes and backslashes
		"\\\\evil.com", "\\/evil.com", "/\\evil.com", "/\\/evil.com",

		// Header injection
		"/path\nHeader: injection", "/path\r\nHeader: injection",
		"/path%0d%0aHeader: injection", "/path\x0d\x0aHeader: injection",

		// Whitespace tricks
		" /valid", "\t/valid", "   ", " //evil.com", "\t//evil.com", "/ /evil.com",

		// Case variations
		"HTTP://evil.com", "HTTPS://evil.com", "JavaScript:alert(1)",

		// Unicode normalization attacks
		"/\u2215\u2215evil.com", "/\uff0f\uff0fevil.com",
	}
}

// checkRelayStateInvariants verifies all security invariants for validateRelayState output.
func checkRelayStateInvariants(t *testing.T, input, result string) {
	t.Helper()

	// Invariant 1: Output is never empty
	if result == "" {
		t.Errorf("validateRelayState(%q) returned empty string", input)
	}

	// Invariant 2: Output always starts with "/"
	if !strings.HasPrefix(result, "/") {
		t.Errorf("validateRelayState(%q) = %q, does not start with /", input, result)
	}

	// Invariant 3: Output never starts with "//" (protocol-relative URL)
	if strings.HasPrefix(result, "//") {
		t.Errorf("validateRelayState(%q) = %q, starts with // (protocol-relative)", input, result)
	}

	// Invariant 4: Parsed URL has no scheme or host
	parsed, err := url.Parse(result)
	if err != nil {
		t.Errorf("validateRelayState(%q) = %q, failed to parse: %v", input, result, err)
	} else {
		if parsed.Scheme != "" {
			t.Errorf("validateRelayState(%q) = %q, has scheme: %q", input, result, parsed.Scheme)
		}
		if parsed.Host != "" {
			t.Errorf("validateRelayState(%q) = %q, has host: %q", input, result, parsed.Host)
		}
	}

	// Invariant 5: Output contains no CR/LF (header injection prevention)
	if strings.ContainsAny(result, "\r\n") {
		t.Errorf("validateRelayState(%q) = %q, contains CR/LF", input, result)
	}
}

// FuzzValidateRelayState tests that validateRelayState always returns safe output.
// Uses minimal seed corpus for fast local development runs.
// Run with -fuzztime=5s for quick checks.
func FuzzValidateRelayState(f *testing.F) {
	for _, seed := range fuzzRelayStateSeeds() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := validateRelayState(input)
		checkRelayStateInvariants(t, input, result)
	})
}
