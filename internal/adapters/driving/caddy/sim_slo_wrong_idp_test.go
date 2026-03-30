//go:build unit

package caddy

// SimSLOWrongIdP documents the IdP-initiated SLO bug in handleSLOInternal:
// the handler calls ListIdPs("") and uses idps[0] as the IdP to validate the
// LogoutRequest, regardless of which IdP actually sent it. This means the
// selected IdP is determined by metadata list order, not by the Issuer in
// the SAMLRequest.
//
// Correct behaviour: parse the Issuer from the LogoutRequest XML and use
// GetIdP(issuer) to look up exactly the right IdP.
//
// See: handlers_logout.go lines 106-111 (the `samlRequest != ""` branch).

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

// TestSimSLOWrongIdP_BugDocumentation proves that the IdP-initiated SLO
// handler uses idps[0] regardless of which IdP sent the LogoutRequest.
//
// The assertion at the end intentionally does NOT check that the correct IdP
// was used — it documents what the handler actually does: blindly selects the
// first IdP from the list.
func TestSimSLOWrongIdP_BugDocumentation(t *testing.T) {
	tra.Require(t, "Adapter.SLOIdPInitiatedWrongIdP")

	// Build a store where IdP B is in the middle of the list.
	// A real SLO LogoutRequest from IdP B should cause the handler to look up
	// IdP B specifically; instead it picks whatever is at index 0.
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{idpA, idpB, idpC})

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs: %v", err)
	}
	if len(idps) == 0 {
		t.Fatal("store returned no IdPs")
	}

	// The handler grabs idps[0] unconditionally (handlers_logout.go:111).
	selectedByHandler := idps[0]

	t.Logf("BUG: handler selects %q (idps[0]) for every IdP-initiated LogoutRequest", selectedByHandler.EntityID)
	t.Logf("     even when the LogoutRequest Issuer is %q or %q", idpB.EntityID, idpC.EntityID)

	// Document: the handler always picks idps[0], which is IdP A here.
	// If IdP B or C sends a LogoutRequest, validation will use IdP A's certificate
	// and SLO URL — the wrong IdP entirely.
	if selectedByHandler.EntityID != idpA.EntityID {
		t.Errorf("expected handler to select %q (idps[0] = IdP A), got %q — re-read handlers_logout.go",
			idpA.EntityID, selectedByHandler.EntityID)
	}
}

// TestSimSLOWrongIdP_MetadataReorderChangesSelection shows that the handler's
// selected IdP changes when metadata order changes, proving the selection is
// order-dependent rather than identity-based.
func TestSimSLOWrongIdP_MetadataReorderChangesSelection(t *testing.T) {
	tra.Require(t, "Adapter.SLOIdPInitiatedWrongIdP")

	// Initial order: [A, B, C] — handler picks A.
	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{idpA, idpB, idpC})

	idps, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs (initial order): %v", err)
	}
	if len(idps) == 0 {
		t.Fatal("initial store returned no IdPs")
	}
	firstBefore := idps[0].EntityID

	// Reverse the order: [C, B, A] — handler now picks C.
	store.Replace([]domain.IdPInfo{idpC, idpB, idpA})

	idpsAfter, err := store.ListIdPs("")
	if err != nil {
		t.Fatalf("ListIdPs (reversed order): %v", err)
	}
	if len(idpsAfter) == 0 {
		t.Fatal("reversed store returned no IdPs")
	}
	firstAfter := idpsAfter[0].EntityID

	t.Logf("Before reorder: handler would use %q", firstBefore)
	t.Logf("After reorder:  handler would use %q", firstAfter)

	// The two selections must differ — the same IdP-initiated LogoutRequest
	// would be validated against a different IdP just because the list changed.
	if firstBefore == firstAfter {
		t.Errorf("expected idps[0] to change after reorder, but got %q both times — "+
			"the test fixture may need adjustment", firstBefore)
	}
}

// TestSimSLOWrongIdP_CorrectBehaviorDocumented describes what the fixed
// implementation must do, without making any assertions against live handler
// code (the fix is not yet applied).
func TestSimSLOWrongIdP_CorrectBehaviorDocumented(t *testing.T) {
	tra.Require(t, "Adapter.SLOIdPInitiatedWrongIdP")

	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{idpA, idpB, idpC})

	// Simulate what the corrected handler should do:
	// 1. Parse the Issuer element from the base64-decoded LogoutRequest XML.
	// 2. Use that entity ID to call GetIdP — O(1) lookup, order-independent.
	issuerFromRequest := idpB.EntityID // as if extracted from the SAMLRequest XML

	idp, err := store.GetIdP(issuerFromRequest)
	if err != nil {
		t.Fatalf("GetIdP(%q): %v — store must be able to find IdP B by entity ID", issuerFromRequest, err)
	}

	t.Logf("CORRECT: GetIdP(%q) returns the right IdP: %q", issuerFromRequest, idp.EntityID)

	if idp.EntityID != idpB.EntityID {
		t.Errorf("expected %q, got %q", idpB.EntityID, idp.EntityID)
	}

	t.Log("Fix required: decode SAMLRequest, parse <samlp:LogoutRequest><saml:Issuer>, " +
		"then call GetIdP(issuer) instead of ListIdPs(\"\")[0]")
}
