//go:build unit

package caddy

import (
	"errors"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/request"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// TestSimACSCertRotation documents the known limitation that a metadata refresh
// occurring between AuthnRequest dispatch and ACS callback can cause the IdP
// lookup to fail when the rotated metadata carries different entity IDs.
//
// HandleACS re-looks up the IdP from the live metadata store at callback time
// (using the Issuer extracted from the SAMLResponse). If a background refresh
// replaced the metadata between the two operations, the previously-known entity
// ID may no longer exist — producing ErrIdPNotFound and breaking the in-flight
// auth flow.
//
// This test documents the race by driving the lookup layer directly, without
// requiring a real SAML response or valid XML signatures.
func TestSimACSCertRotation(t *testing.T) {
	tra.Require(t, "Adapter.ACS.MetadataCertRotationLimitation")

	const originalEntityID = "https://idp.example.com/saml"
	const rotatedEntityID = "https://idp.example.com/saml/v2" // entity ID changes after rotation

	// --- Phase 1: pre-rotation state ---
	// The SP dispatched an AuthnRequest to originalEntityID. A request ID was
	// stored in the request store to track the in-flight flow.

	requestStore := request.NewInMemoryRequestStore()
	inFlightRequestID := "samlrequest-in-flight-001"
	requestStore.Store(inFlightRequestID, time.Now().Add(10*time.Minute))

	originalIdP := domain.IdPInfo{
		EntityID:    originalEntityID,
		DisplayName: "Example University",
		SSOURL:      "https://idp.example.com/sso",
		SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{
			// Placeholder PEM: a real deployment would have the IdP's signing cert.
			"-----BEGIN CERTIFICATE-----\nMIIBpDCCAQ2gAwIBAgIBATANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdleDEu\nMA0GCSqGSIb3DQEBCwUAA4IBAQCfakeOriginalCertData\n-----END CERTIFICATE-----",
		},
	}

	store := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{originalIdP})

	// Confirm the IdP is reachable before rotation.
	idp, err := store.GetIdP(originalEntityID)
	if err != nil {
		t.Fatalf("pre-rotation: expected to find IdP %q, got error: %v", originalEntityID, err)
	}
	if idp.EntityID != originalEntityID {
		t.Fatalf("pre-rotation: wrong entity ID: got %q, want %q", idp.EntityID, originalEntityID)
	}
	t.Logf("pre-rotation: IdP %q found with %d certificate(s)", idp.EntityID, len(idp.Certificates))

	// --- Phase 2: metadata refresh occurs mid-flight ---
	// The federation operator rotated the IdP certificate. In some deployments
	// the metadata refresh also changes the entity ID (e.g., from a versioned URL
	// scheme). This simulates Replace() being called by the background refresher
	// while an ACS callback for the original entity ID is in flight.

	rotatedIdP := domain.IdPInfo{
		EntityID:    rotatedEntityID,
		DisplayName: "Example University",
		SSOURL:      "https://idp.example.com/sso",
		SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{
			// New certificate after rotation.
			"-----BEGIN CERTIFICATE-----\nMIIBpDCCAQ2gAwIBAgIBATANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdleDIu\nMA0GCSqGSIb3DQEBCwUAA4IBAQCfakeRotatedCertData\n-----END CERTIFICATE-----",
		},
	}

	store.Replace([]domain.IdPInfo{rotatedIdP})
	t.Log("metadata rotated: store now contains only the rotated entity ID")

	// --- Phase 3: ACS callback arrives for the original entity ID ---
	// HandleACS extracts the Issuer from the SAMLResponse and calls GetIdP.
	// The Issuer still carries the original entity ID because the SAMLResponse
	// was signed by the old key before rotation.

	_, err = store.GetIdP(originalEntityID)

	// KNOWN LIMITATION: the lookup fails because the metadata was replaced.
	// HandleACS would return an "Unknown identity provider" error to the user,
	// even though the user authenticated successfully at the IdP.
	if !errors.Is(err, domain.ErrIdPNotFound) {
		t.Fatalf("post-rotation: expected ErrIdPNotFound for original entity ID %q, got: %v", originalEntityID, err)
	}
	t.Logf(
		"KNOWN LIMITATION: GetIdP(%q) returned ErrIdPNotFound after metadata rotation. "+
			"HandleACS would reject this in-flight SAML response with 'Unknown identity provider'. "+
			"Mitigation: ensure metadata refresh preserves entity IDs, or extend the request store "+
			"TTL to cover the metadata refresh window.",
		originalEntityID,
	)

	// The rotated entity ID is findable, but the in-flight SAMLResponse carries
	// the original Issuer — so it cannot benefit from the rotated entry.
	rotated, err := store.GetIdP(rotatedEntityID)
	if err != nil {
		t.Fatalf("post-rotation: expected rotated IdP %q to be findable, got: %v", rotatedEntityID, err)
	}
	t.Logf("post-rotation: rotated IdP %q is present with %d certificate(s)", rotated.EntityID, len(rotated.Certificates))

	// The request store still holds the original in-flight entry, demonstrating
	// that the request tracking is intact — only the metadata lookup is broken.
	if !requestStore.Valid(inFlightRequestID) {
		t.Fatal("post-rotation: in-flight request ID should still be valid in request store")
	}
}
