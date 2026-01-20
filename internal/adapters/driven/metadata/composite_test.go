//go:build unit

package metadata

import (
	"context"
	"errors"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// TestCompositeStore_GetIdP_SingleSource tests GetIdP with one wrapped store.
func TestCompositeStore_GetIdP_SingleSource(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}
	store1 := NewInMemoryMetadataStore([]domain.IdPInfo{idp1})

	composite := NewCompositeMetadataStore([]ports.MetadataStore{store1})

	result, err := composite.GetIdP("https://idp1.example.org")
	if err != nil {
		t.Fatalf("GetIdP() failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil IdPInfo")
	}
	if result.EntityID != "https://idp1.example.org" {
		t.Errorf("expected EntityID 'https://idp1.example.org', got %q", result.EntityID)
	}
}

// TestCompositeStore_GetIdP_MultipleSource tests GetIdP returns first match from multiple stores.
func TestCompositeStore_GetIdP_MultipleSource(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}
	idp2 := domain.IdPInfo{EntityID: "https://idp2.example.org", DisplayName: "IdP 2"}
	idp3 := domain.IdPInfo{EntityID: "https://idp3.example.org", DisplayName: "IdP 3"}

	store1 := NewInMemoryMetadataStore([]domain.IdPInfo{idp1})
	store2 := NewInMemoryMetadataStore([]domain.IdPInfo{idp2, idp3})

	composite := NewCompositeMetadataStore([]ports.MetadataStore{store1, store2})

	// Test finding IdP from first store
	result, err := composite.GetIdP("https://idp1.example.org")
	if err != nil {
		t.Fatalf("GetIdP() for idp1 failed: %v", err)
	}
	if result == nil || result.EntityID != "https://idp1.example.org" {
		t.Errorf("expected to find idp1, got %v", result)
	}

	// Test finding IdP from second store
	result, err = composite.GetIdP("https://idp2.example.org")
	if err != nil {
		t.Fatalf("GetIdP() for idp2 failed: %v", err)
	}
	if result == nil || result.EntityID != "https://idp2.example.org" {
		t.Errorf("expected to find idp2, got %v", result)
	}
}

// TestCompositeStore_ListIdPs_Aggregation tests ListIdPs combines results from all stores.
func TestCompositeStore_ListIdPs_Aggregation(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}
	idp2 := domain.IdPInfo{EntityID: "https://idp2.example.org", DisplayName: "IdP 2"}
	idp3 := domain.IdPInfo{EntityID: "https://idp3.example.org", DisplayName: "IdP 3"}

	store1 := NewInMemoryMetadataStore([]domain.IdPInfo{idp1, idp2})
	store2 := NewInMemoryMetadataStore([]domain.IdPInfo{idp3})

	composite := NewCompositeMetadataStore([]ports.MetadataStore{store1, store2})

	result, err := composite.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 IdPs, got %d", len(result))
	}

	// Check all IdPs are present
	entityIDs := make(map[string]bool)
	for _, idp := range result {
		entityIDs[idp.EntityID] = true
	}
	if !entityIDs["https://idp1.example.org"] {
		t.Error("expected idp1 in results")
	}
	if !entityIDs["https://idp2.example.org"] {
		t.Error("expected idp2 in results")
	}
	if !entityIDs["https://idp3.example.org"] {
		t.Error("expected idp3 in results")
	}
}

// TestCompositeStore_ListIdPs_Deduplication tests duplicate EntityIDs are deduplicated (first wins).
func TestCompositeStore_ListIdPs_Deduplication(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1 Store 1"}
	idp1Dup := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1 Store 2"}
	idp2 := domain.IdPInfo{EntityID: "https://idp2.example.org", DisplayName: "IdP 2"}

	store1 := NewInMemoryMetadataStore([]domain.IdPInfo{idp1, idp2})
	store2 := NewInMemoryMetadataStore([]domain.IdPInfo{idp1Dup})

	composite := NewCompositeMetadataStore([]ports.MetadataStore{store1, store2})

	result, err := composite.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 unique IdPs, got %d", len(result))
	}

	// Check that the first version was kept
	for _, idp := range result {
		if idp.EntityID == "https://idp1.example.org" && idp.DisplayName != "IdP 1 Store 1" {
			t.Errorf("expected first version of idp1 to be kept, got DisplayName %q", idp.DisplayName)
		}
	}
}

// TestCompositeStore_EmptyStores tests handling of empty/nil store slice.
func TestCompositeStore_EmptyStores(t *testing.T) {
	composite := NewCompositeMetadataStore([]ports.MetadataStore{})

	// GetIdP should return error when no stores
	_, err := composite.GetIdP("https://idp1.example.org")
	if !errors.Is(err, domain.ErrIdPNotFound) {
		t.Errorf("expected ErrIdPNotFound, got %v", err)
	}

	// ListIdPs should return empty slice
	result, err := composite.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 IdPs, got %d", len(result))
	}
}

// TestCompositeStore_Load tests that Load() calls Load() on all wrapped stores.
func TestCompositeStore_Load(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}
	idp2 := domain.IdPInfo{EntityID: "https://idp2.example.org", DisplayName: "IdP 2"}

	store1 := NewInMemoryMetadataStore([]domain.IdPInfo{idp1})
	store2 := NewInMemoryMetadataStore([]domain.IdPInfo{idp2})

	composite := NewCompositeMetadataStore([]ports.MetadataStore{store1, store2})

	err := composite.Load()
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	// Verify both stores' IdPs are accessible
	result, err := composite.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 IdPs after Load(), got %d", len(result))
	}
}

// TestCompositeStore_Refresh_AllSucceed tests Refresh when all stores succeed.
func TestCompositeStore_Refresh_AllSucceed(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}
	idp2 := domain.IdPInfo{EntityID: "https://idp2.example.org", DisplayName: "IdP 2"}

	store1 := NewInMemoryMetadataStore([]domain.IdPInfo{idp1})
	store2 := NewInMemoryMetadataStore([]domain.IdPInfo{idp2})

	composite := NewCompositeMetadataStore([]ports.MetadataStore{store1, store2})

	ctx := context.Background()
	err := composite.Refresh(ctx)
	if err != nil {
		t.Fatalf("Refresh() failed: %v", err)
	}
}

// TestCompositeStore_Refresh_PartialFailure tests Refresh continues on failure and collects errors.
func TestCompositeStore_Refresh_PartialFailure(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}

	// Create a store that fails on Refresh
	failingStore := &FailingMetadataStore{
		err: errors.New("network timeout"),
	}
	successStore := NewInMemoryMetadataStore([]domain.IdPInfo{idp1})

	composite := NewCompositeMetadataStore([]ports.MetadataStore{failingStore, successStore})

	ctx := context.Background()
	err := composite.Refresh(ctx)
	// Should return an error (from failing store), but should have tried both
	if err == nil {
		t.Fatalf("expected Refresh to return error, got nil")
	}
}

// TestCompositeStore_Health_AllHealthy tests Health when all stores are fresh.
func TestCompositeStore_Health_AllHealthy(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}
	idp2 := domain.IdPInfo{EntityID: "https://idp2.example.org", DisplayName: "IdP 2"}

	store1 := NewInMemoryMetadataStore([]domain.IdPInfo{idp1})
	store2 := NewInMemoryMetadataStore([]domain.IdPInfo{idp2})

	composite := NewCompositeMetadataStore([]ports.MetadataStore{store1, store2})

	health := composite.Health()
	if !health.IsFresh {
		t.Errorf("expected IsFresh=true when all stores fresh, got %v", health.IsFresh)
	}
	if health.IdPCount != 2 {
		t.Errorf("expected IdPCount=2, got %d", health.IdPCount)
	}
}

// TestCompositeStore_Health_SomeDegraded tests Health with mix of fresh/stale stores.
func TestCompositeStore_Health_SomeDegraded(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}
	idp2 := domain.IdPInfo{EntityID: "https://idp2.example.org", DisplayName: "IdP 2"}

	// Fresh store
	freshStore := NewInMemoryMetadataStore([]domain.IdPInfo{idp1})

	// Stale store (created with custom health)
	staleStore := &HealthyMetadataStore{
		idps: []domain.IdPInfo{idp2},
		health: domain.MetadataHealth{
			IsFresh:  false,
			IdPCount: 1,
		},
	}

	composite := NewCompositeMetadataStore([]ports.MetadataStore{freshStore, staleStore})

	health := composite.Health()
	// Worst status wins: stale beats fresh
	if health.IsFresh {
		t.Errorf("expected IsFresh=false when any store is stale, got %v", health.IsFresh)
	}
	if health.IdPCount != 2 {
		t.Errorf("expected IdPCount=2, got %d", health.IdPCount)
	}
}

// TestCompositeStore_Health_AllUnhealthy tests Health when all stores are stale.
func TestCompositeStore_Health_AllUnhealthy(t *testing.T) {
	idp1 := domain.IdPInfo{EntityID: "https://idp1.example.org", DisplayName: "IdP 1"}
	idp2 := domain.IdPInfo{EntityID: "https://idp2.example.org", DisplayName: "IdP 2"}

	// Both stores stale
	staleStore1 := &HealthyMetadataStore{
		idps: []domain.IdPInfo{idp1},
		health: domain.MetadataHealth{
			IsFresh:  false,
			IdPCount: 1,
		},
	}
	staleStore2 := &HealthyMetadataStore{
		idps: []domain.IdPInfo{idp2},
		health: domain.MetadataHealth{
			IsFresh:  false,
			IdPCount: 1,
		},
	}

	composite := NewCompositeMetadataStore([]ports.MetadataStore{staleStore1, staleStore2})

	health := composite.Health()
	if health.IsFresh {
		t.Errorf("expected IsFresh=false when all stores stale, got %v", health.IsFresh)
	}
	if health.IdPCount != 2 {
		t.Errorf("expected IdPCount=2, got %d", health.IdPCount)
	}
}
