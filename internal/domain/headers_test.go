//go:build unit

package domain

import (
	"testing"
)

func TestASCIIToLower(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"abc", "abc"},
		{"ABC", "abc"},
		{"AbC", "abc"},
		{"X-Custom-Header", "x-custom-header"},
		{"Content-Type", "content-type"},
		{"123", "123"},
		{"A-B-C", "a-b-c"},
		// Non-ASCII unchanged
		{"Über", "Über"},   // Ü stays uppercase (non-ASCII)
		{"NAÏVE", "naÏve"}, // Ï stays uppercase (non-ASCII)
		{"日本語", "日本語"},     // Japanese unchanged
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := ASCIIToLower(tc.input)
			if got != tc.want {
				t.Errorf("ASCIIToLower(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestASCIIEqualFold(t *testing.T) {
	tests := []struct {
		s, t string
		want bool
	}{
		{"", "", true},
		{"a", "a", true},
		{"A", "a", true},
		{"a", "A", true},
		{"ABC", "abc", true},
		{"abc", "ABC", true},
		{"AbC", "aBc", true},
		{"X-Custom-Header", "x-custom-header", true},
		{"Content-Type", "content-type", true},
		{"CONTENT-TYPE", "Content-Type", true},
		// Different lengths
		{"a", "ab", false},
		{"ab", "a", false},
		// Different content
		{"abc", "abd", false},
		{"abc", "abC", true}, // C and c are equal
		// Non-ASCII - these should NOT match since we only fold ASCII
		{"Über", "über", false}, // Ü != ü in ASCII-only comparison
		{"NAÏVE", "naïve", false},
	}

	for _, tc := range tests {
		name := tc.s + "_" + tc.t
		t.Run(name, func(t *testing.T) {
			got := ASCIIEqualFold(tc.s, tc.t)
			if got != tc.want {
				t.Errorf("ASCIIEqualFold(%q, %q) = %v, want %v", tc.s, tc.t, got, tc.want)
			}
		})
	}
}

func TestASCIIEqualFold_Symmetry(t *testing.T) {
	pairs := []struct{ s, t string }{
		{"abc", "ABC"},
		{"X-Header", "x-header"},
		{"Content-Type", "CONTENT-TYPE"},
	}

	for _, p := range pairs {
		if ASCIIEqualFold(p.s, p.t) != ASCIIEqualFold(p.t, p.s) {
			t.Errorf("ASCIIEqualFold is not symmetric for %q and %q", p.s, p.t)
		}
	}
}
