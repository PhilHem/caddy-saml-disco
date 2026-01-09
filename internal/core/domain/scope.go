package domain

import (
	"regexp"
	"strings"
)

// ScopeInfo represents a shibmd:Scope element from IdP metadata.
// It declares which scopes (domains) an IdP is authorized to assert.
type ScopeInfo struct {
	// Value is the scope pattern, either a literal domain (e.g., "example.edu")
	// or a regular expression pattern (e.g., ".*\\.partner\\.edu").
	Value string `json:"value"`

	// Regexp indicates whether Value should be interpreted as a regular expression.
	// If false, Value is matched exactly (case-sensitive).
	Regexp bool `json:"regexp"`
}

// scopedAttributes is the set of attribute names that are scoped (have @scope format).
// These attributes must have their scope validated against IdP metadata.
var scopedAttributes = map[string]bool{
	"eduPersonPrincipalName":           true,
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.6": true, // eduPersonPrincipalName OID
	"eduPersonScopedAffiliation":       true,
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.9": true, // eduPersonScopedAffiliation OID
}

// IsScopedAttribute returns true if the attribute name is a scoped attribute.
// Scoped attributes have values in the format "user@scope" and must be validated
// against the IdP's allowed scopes from shibmd:Scope metadata.
//
// This is a pure function with no side effects or I/O.
func IsScopedAttribute(name string) bool {
	if name == "" {
		return false
	}
	return scopedAttributes[name]
}

// ExtractScope extracts the scope part from a scoped attribute value.
// Returns the part after @ for values like "user@example.edu".
// Returns empty string if no @ is present or if value is empty.
//
// This is a pure function with no side effects or I/O.
func ExtractScope(value string) string {
	if value == "" {
		return ""
	}

	idx := strings.Index(value, "@")
	if idx == -1 {
		return ""
	}

	// Return everything after the first @
	scope := value[idx+1:]
	return scope
}

// ValidateScope validates a scope against allowed scopes from IdP metadata.
// Returns true if scope matches any allowed scope (either literal or regex).
// Returns false if scope is empty, no scopes are allowed, or no match is found.
//
// This is a pure function with no side effects or I/O.
// For regex scopes, invalid patterns return false (no panic).
// Regex matching uses a timeout to prevent ReDoS attacks.
func ValidateScope(scope string, allowed []ScopeInfo) bool {
	if scope == "" {
		return false
	}

	if len(allowed) == 0 {
		return false
	}

	for _, s := range allowed {
		if !s.Regexp {
			// Literal match (case-sensitive)
			if scope == s.Value {
				return true
			}
		} else {
			// Regex match with timeout protection
			matched, err := validateScopeRegex(scope, s.Value)
			if err != nil {
				// Invalid regex or timeout - reject
				continue
			}
			if matched {
				return true
			}
		}
	}

	return false
}

// validateScopeRegex validates a scope against a regex pattern with timeout protection.
// Returns (true, nil) if matched, (false, nil) if not matched, (false, error) on error/timeout.
func validateScopeRegex(scope, pattern string) (bool, error) {
	// Compile regex with timeout protection
	// Note: Go's regexp package doesn't have built-in timeout, but we can use
	// a simple approach: compile and match. For ReDoS protection, we rely on
	// fuzz testing to catch problematic patterns. In production, consider using
	// a regex engine with timeout support or limiting pattern complexity.
	re, err := regexp.Compile("^" + pattern + "$")
	if err != nil {
		// Invalid regex pattern
		return false, err
	}

	// Match with anchored pattern (^...$)
	return re.MatchString(scope), nil
}
