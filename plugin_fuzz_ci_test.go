//go:build fuzz_extended

package caddysamldisco

import "testing"

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
