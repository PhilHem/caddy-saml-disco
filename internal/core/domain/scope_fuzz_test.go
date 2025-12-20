//go:build go1.18 && unit

package domain

import (
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Minimal Fuzz Seeds (Local Development - Fast)
// =============================================================================

func fuzzScopeValidationSeeds() []struct {
	pattern string
	input   string
	regexp  bool
} {
	return []struct {
		pattern string
		input   string
		regexp  bool
	}{
		// Valid literal scopes
		{"example.edu", "example.edu", false},
		{"example.edu", "evil.edu", false},

		// Valid regex scopes
		{`.*\.partner\.edu`, "sub.partner.edu", true},
		{`.*\.partner\.edu`, "partner.edu", true},
		{`sub\.partner\.edu`, "sub.partner.edu", true},
		{`sub\.partner\.edu`, "other.partner.edu", false},

		// ReDoS attack patterns
		{"(a+)+$", strings.Repeat("a", 100) + "!", true},
		{"(a|a)+", strings.Repeat("a", 30), true},
		{"(a*)*", strings.Repeat("a", 50), true},
		{"(a+)+", strings.Repeat("a", 20) + "b", true},

		// Invalid regex patterns
		{"[invalid", "test", true},  // Unclosed bracket
		{"(unclosed", "test", true}, // Unclosed paren
		{"*invalid", "test", true},  // Invalid quantifier position

		// Edge cases
		{"", "test", false},
		{"test", "", false},
		{".*", "anything", true},
		{"^test$", "test", true},
	}
}

// =============================================================================
// Fuzz Tests
// =============================================================================

// FuzzValidateScopeRegex tests regex scope validation with ReDoS prevention.
// This fuzz test ensures that regex matching completes within a reasonable timeout
// and doesn't panic on invalid patterns.
func FuzzValidateScopeRegex(f *testing.F) {
	// Add seed corpus
	for _, seed := range fuzzScopeValidationSeeds() {
		f.Add(seed.pattern, seed.input, seed.regexp)
	}

	f.Fuzz(func(t *testing.T, pattern, input string, isRegex bool) {
		scope := ScopeInfo{
			Value:  pattern,
			Regexp: isRegex,
		}

		// Must complete within timeout (ReDoS prevention)
		done := make(chan bool, 1)
		var result bool

		go func() {
			result = ValidateScope(input, []ScopeInfo{scope})
			done <- true
		}()

		select {
		case <-done:
			// Success - function completed
			// Verify invariants
			checkScopeValidationInvariantsFuzz(t, input, []ScopeInfo{scope}, result)
		case <-time.After(100 * time.Millisecond):
			t.Errorf("ReDoS: ValidateScope took too long (>100ms) with pattern %q and input %q", pattern, input)
		}
	})
}

// checkScopeValidationInvariantsFuzz is the fuzz-specific invariant checker.
// It uses t.Errorf instead of t.Fatal to allow fuzz to continue finding issues.
func checkScopeValidationInvariantsFuzz(t *testing.T, scope string, allowed []ScopeInfo, result bool) {
	t.Helper()

	// Invariant 1: Empty scope always returns false
	if scope == "" && result {
		t.Errorf("invariant 1 violated: empty scope returned true")
	}

	// Invariant 2: Empty allowed list always returns false
	if len(allowed) == 0 && result {
		t.Errorf("invariant 2 violated: empty allowed list returned true")
	}

	// Invariant 3: No panic (implicit - test completes)
	// If we got here, no panic occurred

	// Invariant 4: Result is boolean (implicit - type system)
}

// FuzzExtractScope tests scope extraction from attribute values.
// Ensures no panics and handles edge cases like multiple @ symbols.
func FuzzExtractScope(f *testing.F) {
	// Seed corpus
	f.Add("user@example.edu")
	f.Add("admin")
	f.Add("user@sub@example.edu")
	f.Add("@example.edu")
	f.Add("")
	f.Add("no-at-symbol")
	f.Add("multiple@at@symbols@here.edu")

	f.Fuzz(func(t *testing.T, value string) {
		// Should never panic
		scope := ExtractScope(value)

		// Invariant: If value contains @, scope should be non-empty (unless @ is at end)
		if strings.Contains(value, "@") && !strings.HasSuffix(value, "@") {
			if scope == "" {
				t.Errorf("ExtractScope(%q) returned empty string but value contains @", value)
			}
		}

		// Invariant: If value doesn't contain @, scope should be empty
		if !strings.Contains(value, "@") && scope != "" {
			t.Errorf("ExtractScope(%q) returned %q but value has no @", value, scope)
		}

		// Invariant: Scope should be everything after the first @
		// Note: If input has multiple @ symbols, scope will contain @ (this is expected)
		// The scope is the part after the first @, which may include additional @ symbols
		firstAt := strings.Index(value, "@")
		if firstAt != -1 {
			expectedScope := value[firstAt+1:]
			if scope != expectedScope {
				t.Errorf("ExtractScope(%q) = %q, want %q", value, scope, expectedScope)
			}
		}
	})
}






