//go:build unit

package domain

import (
	"strings"
	"testing"
)

// FuzzMatchesSubjectPattern tests that MatchesSubjectPattern handles arbitrary input safely.
func FuzzMatchesSubjectPattern(f *testing.F) {
	seeds := [][]string{
		{"user@example.edu", "*@example.edu"},
		{"", "*"},
		{strings.Repeat("a", 10000), "*"},
		{"admin@example.edu", "admin@example.edu"},
		{"staff@mit.edu", "staff@*"},
		{"other@foo.com", "*@example.edu"},
	}

	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, subject, pattern string) {
		// Must never panic
		_ = MatchesSubjectPattern(subject, pattern)
	})
}
