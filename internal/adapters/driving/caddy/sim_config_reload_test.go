//go:build unit

package caddy

import (
	"fmt"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/request"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// TestSimConfigReload_RequestIDLostAfterReload verifies that a config reload (new store
// instance) cannot see request IDs stored in the previous instance, while the original
// store retains them.
func TestSimConfigReload_RequestIDLostAfterReload(t *testing.T) {
	tra.Require(t, "Adapter.ConfigReload.RequestIDLost")
	t.Log("Limitation: Caddy config reload creates a fresh request store. Any in-flight SAML flow " +
		"(AuthnRequest sent, ACS response not yet received) will fail because the new store has no " +
		"record of the original request ID.")

	store1 := request.NewInMemoryRequestStore()
	store1.Store("req-123", time.Now().Add(10*time.Minute))

	// Simulate config reload: a second, independent store instance.
	store2 := request.NewInMemoryRequestStore()

	// store2 must not find the ID — it is a fresh instance.
	if store2.Valid("req-123") {
		t.Error("store2.Valid(\"req-123\") = true; new store after reload must not know about pre-reload request IDs")
	}

	// store1 must still find the ID — it was never consumed.
	if !store1.Valid("req-123") {
		t.Error("store1.Valid(\"req-123\") = false; original store should still hold the request ID")
	}
}

// TestSimConfigReload_MultipleInFlightRequestsLost verifies that all 100 in-flight request
// IDs present in store1 are invisible to store2 (the post-reload instance), while store1
// itself still reports them all as valid.
func TestSimConfigReload_MultipleInFlightRequestsLost(t *testing.T) {
	tra.Require(t, "Adapter.ConfigReload.MultipleRequestsLost")
	t.Log("Limitation: Caddy config reload creates a fresh request store. Any in-flight SAML flow " +
		"(AuthnRequest sent, ACS response not yet received) will fail because the new store has no " +
		"record of the original request ID.")

	const count = 100
	store1 := request.NewInMemoryRequestStore()

	for i := 0; i < count; i++ {
		id := fmt.Sprintf("req-%03d", i)
		store1.Store(id, time.Now().Add(10*time.Minute))
	}

	// Simulate config reload.
	store2 := request.NewInMemoryRequestStore()

	// store2 must be empty.
	if ids := store2.GetAll(); len(ids) != 0 {
		t.Errorf("store2.GetAll() returned %d IDs after reload, want 0", len(ids))
	}

	// All IDs must still be valid in store1.
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("req-%03d", i)
		if !store1.Valid(id) {
			t.Errorf("store1.Valid(%q) = false; expected pre-reload request IDs to still be present", id)
		}
	}
}
