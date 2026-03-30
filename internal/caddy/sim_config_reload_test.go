//go:build unit

package caddy

import (
	"fmt"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// TestConfigReload_RequestIDSurvives verifies that the shared request store allows
// in-flight request IDs to survive across config reloads.
func TestConfigReload_RequestIDSurvives(t *testing.T) {
	tra.Require(t, "Adapter.ConfigReload.RequestIDSurvives")

	// Store an ID using the shared request store
	sharedStore1 := getSharedRequestStore()
	sharedStore1.Store("req-123", time.Now().Add(10*time.Minute))

	// Simulate getting the shared store again (as happens during config reload)
	// The sync.Once ensures we get the same underlying store
	sharedStore2 := getSharedRequestStore()

	// sharedStore2 must find the ID stored by sharedStore1
	if !sharedStore2.Valid("req-123") {
		t.Error("sharedStore2.Valid(\"req-123\") = false; shared store should retain request IDs across reloads")
	}
}

// TestConfigReload_MultipleInFlightRequestsSurvive verifies that multiple in-flight
// request IDs survive across config reloads when using the shared request store.
func TestConfigReload_MultipleInFlightRequestsSurvive(t *testing.T) {
	tra.Require(t, "Adapter.ConfigReload.MultipleRequestsSurvive")

	const count = 100

	// Store 100 request IDs using the shared store
	sharedStore1 := getSharedRequestStore()
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("req-%03d", i)
		sharedStore1.Store(id, time.Now().Add(10*time.Minute))
	}

	// Simulate config reload: get the shared store again
	sharedStore2 := getSharedRequestStore()

	// All IDs must be visible in the reloaded store.
	allIDs := sharedStore2.GetAll()
	if len(allIDs) < count {
		t.Errorf("sharedStore2.GetAll() returned %d IDs after reload, want at least %d", len(allIDs), count)
	}

	// All stored IDs must be valid in the reloaded store
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("req-%03d", i)
		if !sharedStore2.Valid(id) {
			t.Errorf("sharedStore2.Valid(%q) = false; expected pre-reload request IDs to still be present", id)
		}
	}
}
