//go:build unit

package domain

import (
	"testing"
	"testing/quick"
)

// =============================================================================
// ARCH-028: IsValidHeaderName Tests
// =============================================================================

// TestIsValidHeaderName_ValidNames tests that valid header names return true.
func TestIsValidHeaderName_ValidNames(t *testing.T) {
	testCases := []struct {
		name     string
		header   string
		expected bool
	}{
		{"X-User", "X-User", true},
		{"X-Remote-User", "X-Remote-User", true},
		{"x-lowercase", "x-lowercase", true},
		{"X-123", "X-123", true},
		{"X-User-Name", "X-User-Name", true},
		{"X-A", "X-A", true},
		{"X-123-ABC", "X-123-ABC", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidHeaderName(tc.header)
			if result != tc.expected {
				t.Errorf("IsValidHeaderName(%q) = %v, want %v", tc.header, result, tc.expected)
			}
		})
	}
}

// TestIsValidHeaderName_InvalidPrefix tests that names without X- prefix return false.
func TestIsValidHeaderName_InvalidPrefix(t *testing.T) {
	testCases := []struct {
		name     string
		header   string
		expected bool
	}{
		{"User", "User", false},
		{"Remote-User", "Remote-User", false},
		{"Y-User", "Y-User", false},
		{"user", "user", false},
		{"Z-User", "Z-User", false},
		{"A-User", "A-User", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidHeaderName(tc.header)
			if result != tc.expected {
				t.Errorf("IsValidHeaderName(%q) = %v, want %v", tc.header, result, tc.expected)
			}
		})
	}
}

// TestIsValidHeaderName_TooShort tests that names shorter than 3 characters return false.
func TestIsValidHeaderName_TooShort(t *testing.T) {
	testCases := []struct {
		name     string
		header   string
		expected bool
	}{
		{"empty", "", false},
		{"X", "X", false},
		{"X-", "X-", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidHeaderName(tc.header)
			if result != tc.expected {
				t.Errorf("IsValidHeaderName(%q) = %v, want %v", tc.header, result, tc.expected)
			}
		})
	}
}

// TestIsValidHeaderName_InvalidCharacters tests that names with invalid characters return false.
func TestIsValidHeaderName_InvalidCharacters(t *testing.T) {
	testCases := []struct {
		name     string
		header   string
		expected bool
	}{
		{"space", "X-User Name", false},
		{"underscore", "X-User_Name", false},
		{"dot", "X-User.Name", false},
		{"at", "X-User@Name", false},
		{"special", "X-User#Name", false},
		{"unicode", "X-User\u00E9", false},
		{"tab", "X-User\tName", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidHeaderName(tc.header)
			if result != tc.expected {
				t.Errorf("IsValidHeaderName(%q) = %v, want %v", tc.header, result, tc.expected)
			}
		})
	}
}

// TestIsValidHeaderName_CaseInsensitivePrefix tests that both X- and x- prefixes are valid.
func TestIsValidHeaderName_CaseInsensitivePrefix(t *testing.T) {
	testCases := []struct {
		name     string
		header   string
		expected bool
	}{
		{"uppercase X", "X-User", true},
		{"lowercase x", "x-User", true},
		{"mixed case", "X-user", true},
		{"mixed case 2", "x-USER", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsValidHeaderName(tc.header)
			if result != tc.expected {
				t.Errorf("IsValidHeaderName(%q) = %v, want %v", tc.header, result, tc.expected)
			}
		})
	}
}

// TestIsValidHeaderName_Property_Consistency tests that the function is deterministic.
func TestIsValidHeaderName_Property_Consistency(t *testing.T) {
	f := func(name string) bool {
		// Call function twice with same input
		result1 := IsValidHeaderName(name)
		result2 := IsValidHeaderName(name)
		// Property: same input should always produce same output
		return result1 == result2
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}


