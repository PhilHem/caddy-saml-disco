//go:build unit

package caddy

import (
	"errors"
	"testing"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/metadata"
	"github.com/philiph/caddy-saml-disco/internal/request"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// entityIDStoreAccessor is the interface that InMemoryRequestStore satisfies for entity ID operations.
type entityIDStoreAccessor interface {
	StoreWithEntityID(string, time.Time, string)
	GetEntityID(string) (string, bool)
}

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

// TestSimACSCertRotation_StoreWithEntityID verifies that StoreWithEntityID persists
// the entity ID and GetEntityID recovers it without consuming the request entry.
func TestSimACSCertRotation_StoreWithEntityID(t *testing.T) {
	tra.Require(t, "Adapter.Request.StoreWithEntityID")

	const entityID = "https://idp.example.com/saml"
	const requestID = "samlrequest-entity-id-001"

	store := request.NewInMemoryRequestStore()

	// Verify the store satisfies the extended interface.
	extStore, ok := interface{}(store).(entityIDStoreAccessor)
	if !ok {
		t.Fatal("InMemoryRequestStore does not implement StoreWithEntityID / GetEntityID")
	}

	expiry := time.Now().Add(10 * time.Minute)
	extStore.StoreWithEntityID(requestID, expiry, entityID)

	// GetEntityID must return the stored entity ID without removing the entry.
	gotEntityID, found := extStore.GetEntityID(requestID)
	if !found {
		t.Fatal("GetEntityID returned not-found for a freshly stored request ID")
	}
	if gotEntityID != entityID {
		t.Fatalf("GetEntityID returned %q, want %q", gotEntityID, entityID)
	}

	// The entry must still be present and valid after the non-destructive read.
	if !store.Valid(requestID) {
		t.Error("Valid() returned false after GetEntityID — entry should not have been consumed")
	}

	// After Valid() consumes the entry, GetEntityID must no longer find it.
	gotEntityID, found = extStore.GetEntityID(requestID)
	if found {
		t.Errorf("GetEntityID returned entity ID %q after entry was consumed by Valid()", gotEntityID)
	}
}

// TestSimACSCertRotation_EntityIDNotFoundForExpired verifies that GetEntityID
// returns ("", false) for an expired entry, so the fallback path cannot be
// tricked into recovering a stale entity ID.
func TestSimACSCertRotation_EntityIDNotFoundForExpired(t *testing.T) {
	tra.Require(t, "Adapter.Request.GetEntityIDRejectsExpired")

	const entityID = "https://idp.example.com/saml"
	const requestID = "samlrequest-expired-001"

	store := request.NewInMemoryRequestStore()
	extStore, ok := interface{}(store).(entityIDStoreAccessor)
	if !ok {
		t.Fatal("InMemoryRequestStore does not implement StoreWithEntityID / GetEntityID")
	}

	// Store with a TTL already in the past.
	expiry := time.Now().Add(-1 * time.Second)
	extStore.StoreWithEntityID(requestID, expiry, entityID)

	gotEntityID, found := extStore.GetEntityID(requestID)
	if found {
		t.Errorf("GetEntityID returned entity ID %q for an expired entry, want not-found", gotEntityID)
	}
}

// TestSimACSCertRotation_FallbackLookup documents that after a metadata refresh
// causes GetIdP(issuer) to fail, the entity ID stored alongside the request ID
// can be used to find the rotated IdP entry.
//
// This test drives the lookup layer directly, without requiring a real SAML
// response, to verify the fallback logic independently.
func TestSimACSCertRotation_FallbackLookup(t *testing.T) {
	tra.Require(t, "Adapter.ACS.EntityIDFallbackLookup")

	const originalEntityID = "https://idp.example.com/saml"
	const requestID = "samlrequest-fallback-001"

	store := request.NewInMemoryRequestStore()
	extStore, ok := interface{}(store).(entityIDStoreAccessor)
	if !ok {
		t.Fatal("InMemoryRequestStore does not implement StoreWithEntityID / GetEntityID")
	}

	// Simulate: AuthnRequest dispatched to originalEntityID, entity ID stored.
	extStore.StoreWithEntityID(requestID, time.Now().Add(10*time.Minute), originalEntityID)

	// Simulate: metadata refresh — store now carries the same entity ID (typical rotation
	// that preserves entity ID but replaces certificates).
	rotatedIdP := domain.IdPInfo{
		EntityID:    originalEntityID,
		DisplayName: "Example University",
		SSOURL:      "https://idp.example.com/sso",
		SSOBinding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
		Certificates: []string{
			"-----BEGIN CERTIFICATE-----\nMIIBpDCCAQ2gAwIBAgIBATANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDEwdleDIu\nMA0GCSqGSIb3DQEBCwUAA4IBAQCfakeRotatedCertData\n-----END CERTIFICATE-----",
		},
	}
	metaStore := metadata.NewInMemoryMetadataStore([]domain.IdPInfo{rotatedIdP})

	// Simulate: ACS primary lookup by issuer succeeds here (entity ID unchanged).
	// The fallback matters when the primary lookup fails — test that path explicitly.
	issuer := originalEntityID
	_, primaryErr := metaStore.GetIdP(issuer)
	if primaryErr != nil {
		// Primary lookup failed; use fallback.
		storedEntityID, found := extStore.GetEntityID(requestID)
		if !found || storedEntityID == "" {
			t.Fatal("fallback: GetEntityID returned not-found — cannot recover IdP")
		}
		fallbackIdP, fallbackErr := metaStore.GetIdP(storedEntityID)
		if fallbackErr != nil {
			t.Fatalf("fallback: GetIdP(%q) failed: %v", storedEntityID, fallbackErr)
		}
		if fallbackIdP.EntityID != originalEntityID {
			t.Fatalf("fallback: recovered IdP entity ID = %q, want %q", fallbackIdP.EntityID, originalEntityID)
		}
		t.Logf("fallback: recovered IdP %q via stored entity ID", fallbackIdP.EntityID)
	} else {
		// Primary succeeded — simulate a case where issuer changed to test fallback explicitly.
		changedIssuer := "https://idp.example.com/saml/OLD"
		_, primaryErr2 := metaStore.GetIdP(changedIssuer)
		if !errors.Is(primaryErr2, domain.ErrIdPNotFound) {
			t.Fatalf("expected ErrIdPNotFound for changed issuer, got: %v", primaryErr2)
		}

		// Fallback: recover via stored entity ID.
		storedEntityID, found := extStore.GetEntityID(requestID)
		if !found || storedEntityID == "" {
			t.Fatal("fallback: GetEntityID returned not-found")
		}
		fallbackIdP, fallbackErr := metaStore.GetIdP(storedEntityID)
		if fallbackErr != nil {
			t.Fatalf("fallback: GetIdP(%q) failed: %v", storedEntityID, fallbackErr)
		}
		if fallbackIdP.EntityID != originalEntityID {
			t.Fatalf("fallback: recovered IdP entity ID = %q, want %q", fallbackIdP.EntityID, originalEntityID)
		}
		t.Logf("fallback: recovered IdP %q via stored entity ID after issuer change", fallbackIdP.EntityID)
	}
}
