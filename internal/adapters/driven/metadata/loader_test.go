//go:build unit

package metadata

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

// TestLoadAndProcessMetadata_SuccessPath tests the happy path where metadata
// parses successfully and passes all filters.
func TestLoadAndProcessMetadata_SuccessPath(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.LoadAndProcessMetadata.SuccessPath")

	validXML := []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`)

	cfg := LoaderConfig{
		Source: "test-source",
	}

	result, err := LoadAndProcessMetadata(validXML, cfg)
	if err != nil {
		t.Fatalf("LoadAndProcessMetadata() failed: %v", err)
	}

	if len(result.IdPs) != 1 {
		t.Errorf("expected 1 IdP, got %d", len(result.IdPs))
	}

	if result.IdPs[0].EntityID != "https://idp.example.com" {
		t.Errorf("EntityID = %q, want %q", result.IdPs[0].EntityID, "https://idp.example.com")
	}
}

// TestLoadAndProcessMetadata_SignatureVerification tests that signature
// verification is performed when a verifier is configured.
func TestLoadAndProcessMetadata_SignatureVerification(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.LoadAndProcessMetadata.SignatureVerification")

	validXML := []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`)

	// Test with passing verifier
	t.Run("verifier passes", func(t *testing.T) {
		cfg := LoaderConfig{
			Source:            "test-source",
			SignatureVerifier: &NoopVerifier{},
		}

		result, err := LoadAndProcessMetadata(validXML, cfg)
		if err != nil {
			t.Fatalf("LoadAndProcessMetadata() failed: %v", err)
		}

		if len(result.IdPs) != 1 {
			t.Errorf("expected 1 IdP, got %d", len(result.IdPs))
		}
	})

	// Test with failing verifier
	t.Run("verifier fails", func(t *testing.T) {
		cfg := LoaderConfig{
			Source:            "test-source",
			SignatureVerifier: &FailingVerifier{Err: errors.New("signature invalid")},
		}

		_, err := LoadAndProcessMetadata(validXML, cfg)
		if err == nil {
			t.Fatal("expected error when signature verification fails")
		}

		if !strings.Contains(err.Error(), "signature") {
			t.Errorf("error should mention signature, got: %v", err)
		}
	})
}

// TestLoadAndProcessMetadata_ExpiredMetadataWarning tests that expired metadata
// is rejected and logged appropriately.
func TestLoadAndProcessMetadata_ExpiredMetadataWarning(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.LoadAndProcessMetadata.ExpiredMetadataWarning")

	expiredXML := []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.example.com"
                  validUntil="2020-01-01T00:00:00Z">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`)

	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	cfg := LoaderConfig{
		Source: "test-source",
		Logger: logger,
	}

	_, err := LoadAndProcessMetadata(expiredXML, cfg)
	if err == nil {
		t.Fatal("expected error for expired metadata")
	}

	if !errors.Is(err, domain.ErrMetadataExpired) {
		t.Errorf("expected ErrMetadataExpired, got: %v", err)
	}

	// Verify warning was logged with structured fields
	warnLogs := logs.FilterMessage("metadata expired")
	if warnLogs.Len() == 0 {
		t.Error("expected 'metadata expired' warning log")
	}

	if warnLogs.Len() > 0 {
		fields := warnLogs.All()[0].ContextMap()
		if _, ok := fields["source"]; !ok {
			t.Error("expected source field in log")
		}
	}
}

// TestLoadAndProcessMetadata_FilterFailure tests that filter failures produce
// a comprehensive error message with all failing filters.
func TestLoadAndProcessMetadata_FilterFailure(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.LoadAndProcessMetadata.FilterFailure")

	validXML := []byte(`<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <EntityDescriptor entityID="https://idp1.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`)

	cfg := LoaderConfig{
		Source:    "test-source",
		IdPFilter: "*nonexistent*",
	}

	_, err := LoadAndProcessMetadata(validXML, cfg)
	if err == nil {
		t.Fatal("expected error when filter matches nothing")
	}

	if !strings.Contains(err.Error(), "filter pattern") {
		t.Errorf("error should mention filter pattern, got: %v", err)
	}
}

// TestLoadAndProcessMetadata_ValidUntilReturned tests that validUntil is extracted
// and returned in the result.
func TestLoadAndProcessMetadata_ValidUntilReturned(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.LoadAndProcessMetadata.ValidUntilReturned")

	validXML := []byte(`<?xml version="1.0"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                  entityID="https://idp.example.com"
                  validUntil="2030-12-31T23:59:59Z">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/sso"/>
    </IDPSSODescriptor>
</EntityDescriptor>`)

	cfg := LoaderConfig{
		Source: "test-source",
	}

	result, err := LoadAndProcessMetadata(validXML, cfg)
	if err != nil {
		t.Fatalf("LoadAndProcessMetadata() failed: %v", err)
	}

	if result.ValidUntil == nil {
		t.Fatal("expected ValidUntil to be set")
	}

	expected := time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)
	if !result.ValidUntil.Equal(expected) {
		t.Errorf("ValidUntil = %v, want %v", *result.ValidUntil, expected)
	}
}

// TestLoadAndProcessMetadata_MultipleFilters tests that multiple filters are
// applied in sequence.
func TestLoadAndProcessMetadata_MultipleFilters(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.LoadAndProcessMetadata.MultipleFilters")

	validXML := []byte(`<?xml version="1.0"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
    <EntityDescriptor entityID="https://idp1.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
    <EntityDescriptor entityID="https://idp2.example.com">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
            <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp2.example.com/sso"/>
        </IDPSSODescriptor>
    </EntityDescriptor>
</EntitiesDescriptor>`)

	// All filters fail - error should mention all
	cfg := LoaderConfig{
		Source:                       "test-source",
		IdPFilter:                    "*nonexistent*",
		RegistrationAuthorityFilter:  "https://nonexistent.org",
		EntityCategoryFilter:         "https://nonexistent.org/category",
		AssuranceCertificationFilter: "https://nonexistent.org/cert",
	}

	_, err := LoadAndProcessMetadata(validXML, cfg)
	if err == nil {
		t.Fatal("expected error when multiple filters fail")
	}

	errMsg := err.Error()
	expectedMentions := []string{
		"filter pattern",
		"registration authority filter",
		"entity category filter",
		"assurance certification filter",
	}

	for _, expected := range expectedMentions {
		if !strings.Contains(errMsg, expected) {
			t.Errorf("error should mention %q, got: %q", expected, errMsg)
		}
	}
}

// FailingVerifier is a test double that always fails verification.
type FailingVerifier struct {
	Err error
}

func (v *FailingVerifier) Verify(data []byte) ([]byte, error) {
	return nil, v.Err
}
