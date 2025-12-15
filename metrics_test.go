//go:build unit

package caddysamldisco

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricsRecorder_Interface verifies the MetricsRecorder interface is defined correctly.
// This test will fail to compile if the interface is missing or has wrong signatures.
func TestMetricsRecorder_Interface(t *testing.T) {
	var _ MetricsRecorder = (*mockMetricsRecorder)(nil)
}

// mockMetricsRecorder is a test double that implements MetricsRecorder.
type mockMetricsRecorder struct {
	authAttempts       []authAttemptCall
	sessionsCreated    int
	sessionValidations []bool
	metadataRefreshes  []metadataRefreshCall
}

type authAttemptCall struct {
	idpEntityID string
	success     bool
}

type metadataRefreshCall struct {
	source   string
	success  bool
	idpCount int
}

func (m *mockMetricsRecorder) RecordAuthAttempt(idpEntityID string, success bool) {
	m.authAttempts = append(m.authAttempts, authAttemptCall{idpEntityID, success})
}

func (m *mockMetricsRecorder) RecordSessionCreated() {
	m.sessionsCreated++
}

func (m *mockMetricsRecorder) RecordSessionValidation(valid bool) {
	m.sessionValidations = append(m.sessionValidations, valid)
}

func (m *mockMetricsRecorder) RecordMetadataRefresh(source string, success bool, idpCount int) {
	m.metadataRefreshes = append(m.metadataRefreshes, metadataRefreshCall{source, success, idpCount})
}

// TestNoopMetricsRecorder_Implements verifies NoopMetricsRecorder implements MetricsRecorder.
func TestNoopMetricsRecorder_Implements(t *testing.T) {
	var _ MetricsRecorder = (*NoopMetricsRecorder)(nil)
}

// TestNoopMetricsRecorder_NoPanic verifies NoopMetricsRecorder methods don't panic.
func TestNoopMetricsRecorder_NoPanic(t *testing.T) {
	r := NewNoopMetricsRecorder()

	// These should not panic
	r.RecordAuthAttempt("https://idp.example.com", true)
	r.RecordAuthAttempt("https://idp.example.com", false)
	r.RecordSessionCreated()
	r.RecordSessionValidation(true)
	r.RecordSessionValidation(false)
	r.RecordMetadataRefresh("url", true, 42)
	r.RecordMetadataRefresh("file", false, 0)
}

// TestPrometheusMetricsRecorder_Implements verifies PrometheusMetricsRecorder implements MetricsRecorder.
func TestPrometheusMetricsRecorder_Implements(t *testing.T) {
	var _ MetricsRecorder = (*PrometheusMetricsRecorder)(nil)
}

// TestPrometheusMetricsRecorder_AuthAttempt verifies auth counter increments correctly.
func TestPrometheusMetricsRecorder_AuthAttempt(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewPrometheusMetricsRecorderWithRegistry(reg)

	r.RecordAuthAttempt("https://idp1.example.com", true)
	r.RecordAuthAttempt("https://idp1.example.com", true)
	r.RecordAuthAttempt("https://idp1.example.com", false)
	r.RecordAuthAttempt("https://idp2.example.com", true)

	// Verify success count for idp1
	if got := testutil.ToFloat64(r.authAttemptsTotal.WithLabelValues("https://idp1.example.com", "success")); got != 2 {
		t.Errorf("idp1 success count = %v, want 2", got)
	}

	// Verify failure count for idp1
	if got := testutil.ToFloat64(r.authAttemptsTotal.WithLabelValues("https://idp1.example.com", "failure")); got != 1 {
		t.Errorf("idp1 failure count = %v, want 1", got)
	}

	// Verify success count for idp2
	if got := testutil.ToFloat64(r.authAttemptsTotal.WithLabelValues("https://idp2.example.com", "success")); got != 1 {
		t.Errorf("idp2 success count = %v, want 1", got)
	}
}

// TestPrometheusMetricsRecorder_Sessions verifies session counters work correctly.
func TestPrometheusMetricsRecorder_Sessions(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewPrometheusMetricsRecorderWithRegistry(reg)

	r.RecordSessionCreated()
	r.RecordSessionCreated()
	r.RecordSessionCreated()

	r.RecordSessionValidation(true)
	r.RecordSessionValidation(true)
	r.RecordSessionValidation(false)

	// Verify sessions created count
	if got := testutil.ToFloat64(r.sessionsCreatedTotal); got != 3 {
		t.Errorf("sessions created = %v, want 3", got)
	}

	// Verify valid session validations
	if got := testutil.ToFloat64(r.sessionValidationsTotal.WithLabelValues("valid")); got != 2 {
		t.Errorf("valid session validations = %v, want 2", got)
	}

	// Verify invalid session validations
	if got := testutil.ToFloat64(r.sessionValidationsTotal.WithLabelValues("invalid")); got != 1 {
		t.Errorf("invalid session validations = %v, want 1", got)
	}
}

// TestPrometheusMetricsRecorder_MetadataRefresh verifies metadata metrics work correctly.
func TestPrometheusMetricsRecorder_MetadataRefresh(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewPrometheusMetricsRecorderWithRegistry(reg)

	r.RecordMetadataRefresh("url", true, 42)
	r.RecordMetadataRefresh("url", true, 45)
	r.RecordMetadataRefresh("url", false, 0)
	r.RecordMetadataRefresh("file", true, 10)

	// Verify url success count
	if got := testutil.ToFloat64(r.metadataRefreshTotal.WithLabelValues("url", "success")); got != 2 {
		t.Errorf("url success count = %v, want 2", got)
	}

	// Verify url failure count
	if got := testutil.ToFloat64(r.metadataRefreshTotal.WithLabelValues("url", "failure")); got != 1 {
		t.Errorf("url failure count = %v, want 1", got)
	}

	// Verify file success count
	if got := testutil.ToFloat64(r.metadataRefreshTotal.WithLabelValues("file", "success")); got != 1 {
		t.Errorf("file success count = %v, want 1", got)
	}

	// Verify IdP count gauge (should be last value: 10 from file refresh)
	if got := testutil.ToFloat64(r.metadataIdpCount); got != 10 {
		t.Errorf("idp count = %v, want 10", got)
	}
}

// TestPrometheusMetricsRecorder_DefaultRegistry verifies default registry constructor works.
func TestPrometheusMetricsRecorder_DefaultRegistry(t *testing.T) {
	// Create with default registry - should not panic
	r := NewPrometheusMetricsRecorder()

	// Record some metrics
	r.RecordAuthAttempt("https://idp.example.com", true)
	r.RecordSessionCreated()
	r.RecordMetadataRefresh("url", true, 5)

	// Verify metrics can be gathered
	metrics, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("Gather() failed: %v", err)
	}

	// Look for our metrics
	found := 0
	for _, mf := range metrics {
		switch mf.GetName() {
		case "saml_disco_auth_attempts_total",
			"saml_disco_sessions_created_total",
			"saml_disco_metadata_refresh_total",
			"saml_disco_metadata_idp_count":
			found++
		}
	}

	if found < 4 {
		t.Errorf("found %d metrics, want at least 4", found)
	}
}

// TestSAMLDisco_MetricsRecorder_Enabled verifies PrometheusMetricsRecorder is used when enabled.
func TestSAMLDisco_MetricsRecorder_Enabled(t *testing.T) {
	// Use a custom registry to avoid conflicts with other tests
	reg := prometheus.NewRegistry()
	recorder := NewPrometheusMetricsRecorderWithRegistry(reg)

	s := &SAMLDisco{
		Config: Config{
			MetricsEnabled: true,
		},
	}
	s.SetMetricsRecorder(recorder)

	// Should be a PrometheusMetricsRecorder
	if _, ok := s.metricsRecorder.(*PrometheusMetricsRecorder); !ok {
		t.Errorf("metricsRecorder = %T, want *PrometheusMetricsRecorder", s.metricsRecorder)
	}
}

// TestSAMLDisco_MetricsRecorder_Disabled verifies NoopMetricsRecorder is used when disabled.
func TestSAMLDisco_MetricsRecorder_Disabled(t *testing.T) {
	s := &SAMLDisco{
		Config: Config{
			MetricsEnabled: false,
		},
	}

	// Initialize metrics recorder
	s.initMetricsRecorder()

	// Should be a NoopMetricsRecorder
	if _, ok := s.metricsRecorder.(*NoopMetricsRecorder); !ok {
		t.Errorf("metricsRecorder = %T, want *NoopMetricsRecorder", s.metricsRecorder)
	}
}
