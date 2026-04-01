//go:build unit

package discovery

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// makeIdP builds a minimal IdPInfo for simulation tests.
func makeIdP(letter string) domain.IdPInfo {
	return domain.IdPInfo{
		EntityID:    "https://" + letter + ".example.org/idp",
		DisplayName: "IdP " + letter,
		SSOURL:      "https://" + letter + ".example.org/sso",
	}
}

// TestSimDiscoveryTOCTOU_IdPDisappearsBetweenListAndSelect verifies that a
// GetIdP() call after Replace() returns not-found when the IdP was removed,
// mirroring the list-then-select TOCTOU window in the discovery handler.
func TestSimDiscoveryTOCTOU_IdPDisappearsBetweenListAndSelect(t *testing.T) {
	tra.Require(t, "Adapter.Discovery.TOCTOUIdPDisappears")

	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{
		makeIdP("a"),
		makeIdP("b"),
		makeIdP("c"),
	})

	// Confirm all three are visible.
	listed, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("expected 3 IdPs before Replace, got %d", len(listed))
	}

	// Simulate a metadata refresh that removes IdP B.
	store.Replace([]domain.IdPInfo{makeIdP("a"), makeIdP("c")})

	// A select for the now-removed IdP B must return not-found.
	_, err = store.GetIdP("https://b.example.org/idp")
	if err == nil {
		t.Fatal("expected not-found error after Replace removed IdP B, got nil")
	}
	if !errors.Is(err, domain.ErrIdPNotFound) {
		t.Fatalf("expected ErrIdPNotFound, got %v", err)
	}
}

// TestSimDiscoveryTOCTOU_ConcurrentSelectsDuringRefresh verifies that concurrent
// GetIdP() calls during a mid-burst Replace() produce consistent outcomes: selects
// for surviving IdPs succeed and selects for removed IdPs return not-found, with
// no panics or data races.
func TestSimDiscoveryTOCTOU_ConcurrentSelectsDuringRefresh(t *testing.T) {
	tra.Require(t, "Adapter.Discovery.TOCTOUConcurrentSelects")

	const numIdPs = 10

	// Build the initial set of 10 IdPs.
	initial := make([]domain.IdPInfo, numIdPs)
	for i := range initial {
		// Use letters a–j for readable entity IDs.
		letter := string(rune('a' + i))
		initial[i] = makeIdP(letter)
	}

	store := metadata.NewInMemoryMetadataStore(initial)

	// Barrier so all goroutines start simultaneously.
	var barrier sync.WaitGroup
	barrier.Add(numIdPs + 1) // numIdPs workers + 1 replacer

	var wg sync.WaitGroup
	wg.Add(numIdPs)

	var (
		successCount    atomic.Int32
		notFoundCount   atomic.Int32
		unexpectedCount atomic.Int32
	)

	// Launch one goroutine per IdP, each selecting a different IdP.
	for i := 0; i < numIdPs; i++ {
		i := i
		letter := string(rune('a' + i))
		entityID := "https://" + letter + ".example.org/idp"

		go func() {
			defer wg.Done()
			barrier.Done()
			barrier.Wait() // await full quorum before proceeding

			_, err := store.GetIdP(entityID)
			switch {
			case err == nil:
				successCount.Add(1)
			case errors.Is(err, domain.ErrIdPNotFound):
				notFoundCount.Add(1)
			default:
				unexpectedCount.Add(1)
			}
		}()
	}

	// Mid-burst: replace with the surviving half (a–e only, removing f–j).
	go func() {
		barrier.Done()
		barrier.Wait()

		surviving := make([]domain.IdPInfo, 5)
		for i := range surviving {
			letter := string(rune('a' + i))
			surviving[i] = makeIdP(letter)
		}
		store.Replace(surviving)
	}()

	wg.Wait()

	if n := unexpectedCount.Load(); n > 0 {
		t.Errorf("got %d unexpected (non-ErrIdPNotFound) errors", n)
	}

	total := successCount.Load() + notFoundCount.Load()
	if total != numIdPs {
		t.Errorf("expected %d total outcomes (success + not-found), got %d", numIdPs, total)
	}

	// After all goroutines complete, surviving IdPs must be findable.
	for i := 0; i < 5; i++ {
		letter := string(rune('a' + i))
		entityID := "https://" + letter + ".example.org/idp"
		if _, err := store.GetIdP(entityID); err != nil {
			t.Errorf("surviving IdP %s not found after Replace: %v", entityID, err)
		}
	}

	// Removed IdPs must not be findable.
	for i := 5; i < numIdPs; i++ {
		letter := string(rune('a' + i))
		entityID := "https://" + letter + ".example.org/idp"
		_, err := store.GetIdP(entityID)
		if err == nil {
			t.Errorf("removed IdP %s unexpectedly found after Replace", entityID)
		}
	}
}

// TestSimDiscoveryTOCTOU_NewIdPsAppearBetweenListAndSelect verifies that a
// GetIdP() call after Replace() succeeds for IdPs that were added by the refresh,
// even if they were absent from the prior ListIdPs() snapshot.
func TestSimDiscoveryTOCTOU_NewIdPsAppearBetweenListAndSelect(t *testing.T) {
	tra.Require(t, "Adapter.Discovery.TOCTOUNewIdPsAppear")

	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{
		makeIdP("a"),
		makeIdP("b"),
	})

	// A client sees [A, B] via ListIdPs and chooses to select C (not yet listed).
	listed, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs() failed: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected 2 IdPs before Replace, got %d", len(listed))
	}

	// Metadata refresh adds C and D.
	store.Replace([]domain.IdPInfo{
		makeIdP("a"),
		makeIdP("b"),
		makeIdP("c"),
		makeIdP("d"),
	})

	// C and D must now be selectable.
	for _, letter := range []string{"c", "d"} {
		entityID := "https://" + letter + ".example.org/idp"
		idp, err := store.GetIdP(entityID)
		if err != nil {
			t.Errorf("newly added IdP %s not found after Replace: %v", entityID, err)
			continue
		}
		if idp.EntityID != entityID {
			t.Errorf("GetIdP(%s) returned wrong IdP: %s", entityID, idp.EntityID)
		}
	}
}
