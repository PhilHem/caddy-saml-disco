//go:build go1.18 && unit

package domain

import (
	"math"
	"strings"
	"testing"
)

// fuzzSelectBestLogoSeeds returns seed corpus entries for SelectBestLogo fuzzing.
// Minimal set covers key edge cases: normal, zero, negative, overflow triggers.
func fuzzSelectBestLogoSeeds() []struct {
	h1, w1 int
	url1   string
	h2, w2 int
	url2   string
} {
	return []struct {
		h1, w1 int
		url1   string
		h2, w2 int
		url2   string
	}{
		// Normal cases
		{100, 100, "logo1.png", 200, 200, "logo2.png"},
		{50, 50, "small.png", 100, 100, "large.png"},
		{0, 0, "zero.png", 10, 10, "valid.png"},
		// Negative dimensions
		{-1, 100, "neg1.png", 50, 50, "pos.png"},
		{100, -1, "neg2.png", 50, 50, "pos.png"},
		// Overflow triggers
		{math.MaxInt, 2, "overflow1.png", 1, 1, "tiny.png"},
		{46341, 46341, "near_overflow.png", 100, 100, "normal.png"},  // Just below sqrt(MaxInt32)
		{46342, 46342, "overflow_32bit.png", 100, 100, "normal.png"}, // Overflows on 32-bit
		// Edge cases
		{math.MaxInt, math.MaxInt, "max.png", 1, 1, "min.png"},
		{math.MinInt, math.MinInt, "min.png", 1, 1, "pos.png"},
	}
}

// checkSelectBestLogoInvariants verifies all security invariants for SelectBestLogo output.
func checkSelectBestLogoInvariants(t *testing.T, logos []Logo, result string) {
	t.Helper()

	// P1: No panic (implicit - test completes)

	// P2: Empty input → empty output
	if len(logos) == 0 {
		if result != "" {
			t.Errorf("SelectBestLogo([]) = %q, want empty string", result)
		}
		return
	}

	// P3: Non-empty input → result from input set (after trimming)
	found := false
	for _, logo := range logos {
		if strings.TrimSpace(logo.URL) == result {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SelectBestLogo result %q not in input set (trimmed)", result)
	}

	// P4: If all URLs are empty/whitespace, result should be empty
	// If at least one URL is non-empty after trimming, result should match one of them
	// (This is verified by P3 above)

	// P5: Stable on overflow - function returns some valid URL (not panic/empty)
	// This is verified by P3 above - if we got here, result is from input set
}

// FuzzSelectBestLogo tests that SelectBestLogo handles arbitrary logo dimensions safely.
// Uses minimal seed corpus for fast local development runs.
// Run with: go test -fuzz=FuzzSelectBestLogo -fuzztime=10s ./internal/core/domain/
func FuzzSelectBestLogo(f *testing.F) {
	for _, seed := range fuzzSelectBestLogoSeeds() {
		f.Add(seed.h1, seed.w1, seed.url1, seed.h2, seed.w2, seed.url2)
	}

	f.Fuzz(func(t *testing.T, h1, w1 int, url1 string, h2, w2 int, url2 string) {
		// Build logo slice from fuzzed inputs
		logos := []Logo{
			{Height: h1, Width: w1, URL: url1},
			{Height: h2, Width: w2, URL: url2},
		}

		// Call function under test
		result := SelectBestLogo(logos)

		// Verify invariants
		checkSelectBestLogoInvariants(t, logos, result)
	})
}






