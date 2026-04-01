//go:build unit

package caddy

import (
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

func TestNonClosingStoreForwardsEntityIDMethods(t *testing.T) {
	tra.Require(t, "Adapter.nonClosingStore.ForwardsExtendedRequestStoreInterface")

	store := getSharedRequestStore()

	// The shared store must expose StoreWithEntityID.
	ewStore, ok := store.(interface {
		StoreWithEntityID(string, time.Time, string)
	})
	if !ok {
		t.Fatal("shared store does not implement StoreWithEntityID")
	}

	// The shared store must expose GetEntityID.
	egStore, ok := store.(interface {
		GetEntityID(string) (string, bool)
	})
	if !ok {
		t.Fatal("shared store does not implement GetEntityID")
	}

	requestID := "test-request-id-entity-fwd"
	entityID := "https://idp.example.com/metadata"
	expiry := time.Now().Add(5 * time.Minute)

	ewStore.StoreWithEntityID(requestID, expiry, entityID)

	got, found := egStore.GetEntityID(requestID)
	if !found {
		t.Fatal("expected GetEntityID to return true for stored request ID")
	}
	if got != entityID {
		t.Errorf("GetEntityID: got %q, want %q", got, entityID)
	}

	// Valid() should also confirm the entry exists (and consume it).
	if !store.Valid(requestID) {
		t.Error("expected Valid() to return true for stored request ID")
	}
}
