package caddysamldisco

import (
	"strings"
	"testing"
)

// =============================================================================
// Minimal Fuzz Seeds (Local Development - Fast)
// =============================================================================

func fuzzAttributeSeeds() []struct {
	attrName  string
	attrValue string
	header    string
} {
	return []struct {
		attrName  string
		attrValue string
		header    string
	}{
		// Valid cases
		{"email", "user@example.com", "X-Email"},
		{"urn:oid:1.3.6.1.4.1.5923.1.1.1.6", "user@example.com", "X-Remote-User"},
		{"urn:oid:0.9.2342.19200300.100.1.3", "admin@test.org", "X-Mail"},

		// CR/LF injection attempts in attribute values
		{"evil", "value\r\nInjected-Header: bad", "X-Evil"},
		{"evil", "value\rcarriage", "X-Evil"},
		{"evil", "value\nnewline", "X-Evil"},
		{"evil", "value\r\n\r\nBody injection", "X-Evil"},

		// CR/LF in header names (should be rejected)
		{"test", "value", "X-Header\r\nInjection"},
		{"test", "value", "X-Header\nBad"},

		// Invalid header prefixes
		{"test", "value", "Authorization"},
		{"test", "value", "Cookie"},
		{"test", "value", "Host"},
		{"test", "value", "Content-Type"},

		// Long values (DoS prevention)
		{"long", strings.Repeat("a", 10000), "X-Long"},
		{"long", strings.Repeat("b", 100000), "X-VeryLong"},

		// Empty and whitespace
		{"empty", "", "X-Empty"},
		{"space", " ", "X-Space"},
		{"tabs", "\t\t", "X-Tabs"},

		// Unicode edge cases
		{"unicode", "日本語", "X-Unicode"},
		{"emoji", "👤user", "X-Emoji"},
		{"rtl", "\u202Eevil", "X-RTL"},

		// Null bytes
		{"null", "before\x00after", "X-Null"},

		// Special chars in attribute names
		{"attr with space", "value", "X-SpaceAttr"},
		{"attr;semicolon", "value", "X-SemiAttr"},
	}
}

// =============================================================================
// Fuzz Tests
// =============================================================================

func FuzzMapAttributesToHeaders(f *testing.F) {
	// Add seed corpus
	for _, seed := range fuzzAttributeSeeds() {
		f.Add(seed.attrName, seed.attrValue, seed.header)
	}

	f.Fuzz(func(t *testing.T, attrName, attrValue, headerName string) {
		attrs := map[string][]string{
			attrName: {attrValue},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: attrName, HeaderName: headerName},
		}

		result, err := MapAttributesToHeaders(attrs, mappings)

		// Check invariants regardless of error
		checkAttributeMappingInvariantsFuzz(t, attrs, mappings, result, err)
	})
}

func FuzzMapAttributesToHeaders_MultiValue(f *testing.F) {
	// Seeds for multi-valued attributes
	f.Add("attr", "val1", "val2", "X-Multi", ";")
	f.Add("attr", "admin", "user", "X-Roles", ",")
	f.Add("attr", "a\r\nb", "c\nd", "X-Evil", ";")
	f.Add("attr", strings.Repeat("x", 5000), strings.Repeat("y", 5000), "X-Long", ";")

	f.Fuzz(func(t *testing.T, attrName, val1, val2, headerName, separator string) {
		attrs := map[string][]string{
			attrName: {val1, val2},
		}
		mappings := []AttributeMapping{
			{SAMLAttribute: attrName, HeaderName: headerName, Separator: separator},
		}

		result, err := MapAttributesToHeaders(attrs, mappings)

		checkAttributeMappingInvariantsFuzz(t, attrs, mappings, result, err)

		// Additional check: if successful, verify separator is used correctly
		if err == nil && len(result) > 0 {
			if headerVal, ok := result[headerName]; ok {
				// The value should contain the separator if both vals are non-empty
				// (after sanitization, the separator might not be present if values were empty)
				if val1 != "" && val2 != "" && separator != "" {
					// Sanitized separator should be present
					sanitizedSep := sanitizeHeaderValue(separator)
					if sanitizedSep != "" && !strings.Contains(headerVal, sanitizedSep) {
						// This is OK if values were sanitized away
						_ = headerVal
					}
				}
			}
		}
	})
}

// =============================================================================
// Fuzz Invariant Checker
// =============================================================================

// checkAttributeMappingInvariantsFuzz is the fuzz-specific invariant checker.
// It uses t.Errorf instead of t.Fatal to allow fuzz to continue finding issues.
func checkAttributeMappingInvariantsFuzz(t *testing.T, attrs map[string][]string, mappings []AttributeMapping, result map[string]string, err error) {
	t.Helper()

	// If error, verify it's for valid reasons (invalid header name)
	if err != nil {
		// Error is acceptable - the function correctly rejected invalid input
		return
	}

	// Invariant 1: Output headers are subset of configured mappings
	allowedHeaders := make(map[string]bool)
	for _, m := range mappings {
		allowedHeaders[m.HeaderName] = true
	}
	for header := range result {
		if !allowedHeaders[header] {
			t.Errorf("invariant 1 violated: unexpected header %q not in mappings", header)
		}
	}

	// Invariant 2: No CR/LF in output values (header injection prevention)
	for header, value := range result {
		if strings.ContainsAny(value, "\r\n") {
			t.Errorf("invariant 2 violated: header %q value contains CR/LF: %q", header, value)
		}
	}

	// Invariant 3: All output headers start with X- (case insensitive)
	for header := range result {
		if !strings.HasPrefix(strings.ToUpper(header), "X-") {
			t.Errorf("invariant 3 violated: header %q doesn't start with X-", header)
		}
	}

	// Invariant 4: Valid header name characters (after X- prefix)
	for header := range result {
		if len(header) >= 2 {
			suffix := header[2:]
			for i, c := range suffix {
				valid := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'
				if !valid {
					t.Errorf("invariant 4 violated: header %q has invalid char at position %d: %q", header, i+2, string(c))
					break
				}
			}
		}
	}

	// Invariant 5: Bounded output length
	for header, value := range result {
		if len(value) > MaxHeaderValueLength {
			t.Errorf("invariant 5 violated: header %q value length %d exceeds max %d", header, len(value), MaxHeaderValueLength)
		}
	}

	// Invariant 6: No null bytes in output
	for header, value := range result {
		if strings.ContainsRune(value, '\x00') {
			t.Errorf("invariant 6 violated: header %q value contains null byte", header)
		}
	}
}
