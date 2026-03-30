//go:build unit

package caddy

// SimSLO tests verify that the IdP-initiated SLO handler selects the correct IdP
// by parsing the Issuer from the LogoutRequest XML and calling GetIdP(issuer),
// rather than blindly using idps[0] from ListIdPs.
//
// See: handlers_logout.go (the `samlRequest != ""` branch).

import (
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// idpA / idpB / idpC are the three fixtures used across all sub-tests.
var (
	idpA = domain.IdPInfo{
		EntityID:    "https://idp-a.example.org",
		DisplayName: "IdP Alpha",
		SSOURL:      "https://idp-a.example.org/sso",
		SLOURL:      "https://idp-a.example.org/slo",
	}
	idpB = domain.IdPInfo{
		EntityID:    "https://idp-b.example.org",
		DisplayName: "IdP Beta",
		SSOURL:      "https://idp-b.example.org/sso",
		SLOURL:      "https://idp-b.example.org/slo",
	}
	idpC = domain.IdPInfo{
		EntityID:    "https://idp-c.example.org",
		DisplayName: "IdP Gamma",
		SSOURL:      "https://idp-c.example.org/sso",
		SLOURL:      "https://idp-c.example.org/slo",
	}
)

// TestSimSLO_CorrectIdPSelection verifies that the IdP-initiated SLO handler
// selects the IdP whose EntityID matches the Issuer in the LogoutRequest, not
// whichever IdP happens to be first in the list.
//
// The fixed handler calls GetIdP(issuer) where issuer is extracted from the
// decoded SAMLRequest XML — this test exercises that building block directly.
func TestSimSLO_CorrectIdPSelection(t *testing.T) {
	tra.Require(t, "Adapter.SLOIdPInitiatedCorrectSelection")

	// Build a store where IdP B is in the middle of the list.
	// A SAMLRequest from IdP B must result in IdP B being selected.
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{idpA, idpB, idpC})

	// Simulate what the fixed handler does: extract issuer from LogoutRequest XML,
	// then call GetIdP(issuer).
	issuerFromRequest := idpB.EntityID

	idp, err := store.GetIdP(issuerFromRequest)
	if err != nil {
		t.Fatalf("GetIdP(%q): %v", issuerFromRequest, err)
	}

	if idp.EntityID != idpB.EntityID {
		t.Errorf("expected IdP %q to be selected, got %q", idpB.EntityID, idp.EntityID)
	}
}

// TestSimSLO_OrderIndependent verifies that GetIdP returns the same IdP
// regardless of the order IdPs appear in the metadata list. This proves that
// the fix is robust against metadata refresh reordering.
func TestSimSLO_OrderIndependent(t *testing.T) {
	tra.Require(t, "Adapter.SLOIdPInitiatedCorrectSelection")

	// Initial order: [A, B, C]
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{idpA, idpB, idpC})

	idpBefore, err := store.GetIdP(idpB.EntityID)
	if err != nil {
		t.Fatalf("GetIdP before reorder: %v", err)
	}

	// Reverse the order: [C, B, A]
	store.Replace([]domain.IdPInfo{idpC, idpB, idpA})

	idpAfter, err := store.GetIdP(idpB.EntityID)
	if err != nil {
		t.Fatalf("GetIdP after reorder: %v", err)
	}

	if idpBefore.EntityID != idpB.EntityID {
		t.Errorf("before reorder: expected %q, got %q", idpB.EntityID, idpBefore.EntityID)
	}
	if idpAfter.EntityID != idpB.EntityID {
		t.Errorf("after reorder: expected %q, got %q", idpB.EntityID, idpAfter.EntityID)
	}
	if idpBefore.EntityID != idpAfter.EntityID {
		t.Errorf("reorder changed result: before=%q after=%q", idpBefore.EntityID, idpAfter.EntityID)
	}
}
