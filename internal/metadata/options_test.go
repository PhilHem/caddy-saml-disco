//go:build unit

package metadata

import (
	"testing"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/ports"
	"github.com/philiph/caddy-saml-disco/internal/testutil/tra"
)

func TestProcessMetadataOptions(t *testing.T) {
	tra.Require(t, "Adapter.Metadata.OptionsProcessing")

	t.Run("applies all options correctly", func(t *testing.T) {
		logger := zap.NewNop()
		verifier := &mockVerifier{}
		recorder := &MockMetricsRecorder{}
		clock := NewFakeClock()
		onRefreshFn := func(error) {}

		opts := []MetadataOption{
			WithIdPFilter("*university*"),
			WithRegistrationAuthorityFilter("https://example.org"),
			WithEntityCategoryFilter("http://refeds.org/category/research"),
			WithAssuranceCertificationFilter("https://refeds.org/sirtfi"),
			WithSignatureVerifier(verifier),
			WithLogger(logger),
			WithMetricsRecorder(recorder),
			WithOnRefresh(onRefreshFn),
			WithClock(clock),
			WithVersion("v1.2.3"),
		}

		result := processMetadataOptions(opts)

		if result.idpFilter != "*university*" {
			t.Errorf("idpFilter = %q, want %q", result.idpFilter, "*university*")
		}
		if result.registrationAuthorityFilter != "https://example.org" {
			t.Errorf("registrationAuthorityFilter = %q, want %q", result.registrationAuthorityFilter, "https://example.org")
		}
		if result.entityCategoryFilter != "http://refeds.org/category/research" {
			t.Errorf("entityCategoryFilter = %q, want %q", result.entityCategoryFilter, "http://refeds.org/category/research")
		}
		if result.assuranceCertificationFilter != "https://refeds.org/sirtfi" {
			t.Errorf("assuranceCertificationFilter = %q, want %q", result.assuranceCertificationFilter, "https://refeds.org/sirtfi")
		}
		if result.signatureVerifier != verifier {
			t.Error("signatureVerifier not set correctly")
		}
		if result.logger != logger {
			t.Error("logger not set correctly")
		}
		if result.metricsRecorder != recorder {
			t.Error("metricsRecorder not set correctly")
		}
		if result.onRefresh == nil {
			t.Error("onRefresh not set")
		}
		if result.clock != clock {
			t.Error("clock not set correctly")
		}
		if result.version != "v1.2.3" {
			t.Errorf("version = %q, want %q", result.version, "v1.2.3")
		}
	})

	t.Run("defaults clock to RealClock when not provided", func(t *testing.T) {
		opts := []MetadataOption{}
		result := processMetadataOptions(opts)

		if result.clock == nil {
			t.Error("clock should default to RealClock, got nil")
		}
		if _, ok := result.clock.(RealClock); !ok {
			t.Errorf("clock should default to RealClock, got %T", result.clock)
		}
	})

	t.Run("preserves custom clock when provided", func(t *testing.T) {
		customClock := NewFakeClock()
		opts := []MetadataOption{WithClock(customClock)}
		result := processMetadataOptions(opts)

		if result.clock != customClock {
			t.Error("custom clock should be preserved")
		}
	})

	t.Run("handles empty options slice", func(t *testing.T) {
		result := processMetadataOptions(nil)

		if result.idpFilter != "" {
			t.Errorf("idpFilter should be empty, got %q", result.idpFilter)
		}
		if result.clock == nil {
			t.Error("clock should default to RealClock")
		}
	})
}

// Mock types for testing
type mockVerifier struct{}

func (m *mockVerifier) Verify(data []byte) ([]byte, error) {
	return data, nil
}

var _ ports.SignatureVerifier = (*mockVerifier)(nil)
