//go:build fuzz_extended

package caddysamldisco

import (
	"strings"
	"testing"
	"time"
)

// FuzzValidateRelayStateExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzValidateRelayStateExtended -fuzztime=60s .
func FuzzValidateRelayStateExtended(f *testing.F) {
	for _, seed := range fuzzRelayStateSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		result := validateRelayState(input)
		checkRelayStateInvariants(t, input, result)
	})
}

// fuzzSessionGetSeedsExtended returns the full seed corpus for CI JWT parsing tests.
func fuzzSessionGetSeedsExtended() []string {
	return []string{
		// === All minimal seeds ===
		"",
		"not-a-jwt",
		"a.b.c",
		"header.payload",
		"a.b.c.d.e",
		"eyJhbGciOiJub25lIn0.e30.",
		"!!!.@@@.###",
		"eyJhbGc",
		"eyJ\x00.e30.sig",
		strings.Repeat("a", 10000),

		// === Algorithm confusion attacks ===
		// HS256 header (symmetric key confusion)
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.XmNK3GpH3Ys_7wsYBfq4C3M6goz71I7dTgUkuIa5lyQ",
		// HS384 header
		"eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.e30.signature",
		// HS512 header
		"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.e30.signature",
		// ES256 header (ECDSA)
		"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature",
		// PS256 header (RSA-PSS)
		"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature",

		// === Encoding variations ===
		// URL-safe base64 vs standard
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature",
		// With padding
		"eyJhbGciOiJSUzI1NiJ9==.eyJzdWIiOiJ0ZXN0In0==.c2ln==",
		// Mixed padding
		"eyJhbGciOiJSUzI1NiJ9=.eyJzdWIiOiJ0ZXN0In0.sig",
		// Double-encoded
		"ZXlKaGJHY2lPaUp1YjI1bEluMC5lMzAu",

		// === Boundary conditions ===
		// Single character parts
		"a.b.c",
		// Empty parts
		"...",
		".payload.signature",
		"header..signature",
		"header.payload.",
		// Very long header
		strings.Repeat("eyJ", 5000) + "." + "e30." + "sig",
		// Very long payload
		"eyJhbGciOiJSUzI1NiJ9." + strings.Repeat("eyJ", 5000) + ".sig",
		// Very long signature
		"eyJhbGciOiJSUzI1NiJ9.e30." + strings.Repeat("a", 10000),

		// === Null byte and control character injection ===
		"eyJhbGciOiJSUzI1NiJ9\x00.e30.sig",
		"eyJhbGciOiJSUzI1NiJ9.\x00e30.sig",
		"eyJhbGciOiJSUzI1NiJ9.e30.\x00sig",
		"eyJhbGci\x00OiJSUzI1NiJ9.e30.sig",
		// Newline injection
		"eyJhbGciOiJSUzI1NiJ9\n.e30.sig",
		"eyJhbGciOiJSUzI1NiJ9\r\n.e30.sig",

		// === Unicode attacks ===
		// Unicode null
		"eyJhbGciOiJSUzI1NiJ9\u0000.e30.sig",
		// Full-width characters
		"eyJhbGciOiJSUzI1NiJ9．e30．sig",
		// Unicode dots
		"eyJhbGciOiJSUzI1NiJ9\u2024e30\u2024sig",

		// === Malformed JSON in claims ===
		// Truncated JSON
		"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0.sig",
		// Invalid JSON
		"eyJhbGciOiJSUzI1NiJ9.bm90LWpzb24.sig",
		// Array instead of object
		"eyJhbGciOiJSUzI1NiJ9.W10.sig",

		// === Whitespace tricks ===
		" eyJhbGciOiJSUzI1NiJ9.e30.sig",
		"eyJhbGciOiJSUzI1NiJ9.e30.sig ",
		"\teyJhbGciOiJSUzI1NiJ9.e30.sig",
		"eyJhbGciOiJSUzI1NiJ9 .e30.sig",
		"eyJhbGciOiJSUzI1NiJ9. e30.sig",
		"eyJhbGciOiJSUzI1NiJ9.e30 .sig",
	}
}

// FuzzCookieSessionGetExtended uses the full seed corpus for thorough CI testing.
// Run in CI with: go test -tags=fuzz_extended -fuzz=FuzzCookieSessionGetExtended -fuzztime=60s .
func FuzzCookieSessionGetExtended(f *testing.F) {
	for _, seed := range fuzzSessionGetSeedsExtended() {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		store := NewCookieSessionStore(fuzzTestKey, time.Hour)
		session, err := store.Get(input)
		checkSessionGetInvariants(t, input, session, err)
	})
}
