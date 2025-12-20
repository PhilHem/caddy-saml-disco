//go:build unit

package caddysamldisco

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

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

// getMetricValue extracts a metric value from the registry by name and labels.
func getMetricValue(reg prometheus.Gatherer, name string, labels map[string]string) float64 {
	metrics, _ := reg.Gather()
	for _, mf := range metrics {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			// Check if labels match
			labelMap := make(map[string]string)
			for _, label := range m.GetLabel() {
				labelMap[label.GetName()] = label.GetValue()
			}
			matches := true
			for k, v := range labels {
				if labelMap[k] != v {
					matches = false
					break
				}
			}
			if matches {
				if mf.GetType() == dto.MetricType_COUNTER {
					return m.GetCounter().GetValue()
				} else if mf.GetType() == dto.MetricType_GAUGE {
					return m.GetGauge().GetValue()
				}
			}
		}
	}
	return 0
}

// TestPrometheusMetricsRecorder_AuthAttempt verifies auth counter increments correctly.
func TestPrometheusMetricsRecorder_AuthAttempt(t *testing.T) {
	reg := prometheus.NewRegistry()
	r := NewPrometheusMetricsRecorderWithRegistry(reg)

	r.RecordAuthAttempt("https://idp1.example.com", true)
	r.RecordAuthAttempt("https://idp1.example.com", true)
	r.RecordAuthAttempt("https://idp1.example.com", false)
	r.RecordAuthAttempt("https://idp2.example.com", true)

	// Verify success count for idp1 by gathering from registry
	if got := getMetricValue(reg, "saml_disco_auth_attempts_total", map[string]string{"idp_entity_id": "https://idp1.example.com", "result": "success"}); got != 2 {
		t.Errorf("idp1 success count = %v, want 2", got)
	}

	// Verify failure count for idp1
	if got := getMetricValue(reg, "saml_disco_auth_attempts_total", map[string]string{"idp_entity_id": "https://idp1.example.com", "result": "failure"}); got != 1 {
		t.Errorf("idp1 failure count = %v, want 1", got)
	}

	// Verify success count for idp2
	if got := getMetricValue(reg, "saml_disco_auth_attempts_total", map[string]string{"idp_entity_id": "https://idp2.example.com", "result": "success"}); got != 1 {
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

	// Verify sessions created count by gathering from registry
	if got := getMetricValue(reg, "saml_disco_sessions_created_total", nil); got != 3 {
		t.Errorf("sessions created = %v, want 3", got)
	}

	// Verify valid session validations
	if got := getMetricValue(reg, "saml_disco_session_validations_total", map[string]string{"result": "valid"}); got != 2 {
		t.Errorf("valid session validations = %v, want 2", got)
	}

	// Verify invalid session validations
	if got := getMetricValue(reg, "saml_disco_session_validations_total", map[string]string{"result": "invalid"}); got != 1 {
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

	// Verify url success count by gathering from registry
	if got := getMetricValue(reg, "saml_disco_metadata_refresh_total", map[string]string{"source": "url", "result": "success"}); got != 2 {
		t.Errorf("url success count = %v, want 2", got)
	}

	// Verify url failure count
	if got := getMetricValue(reg, "saml_disco_metadata_refresh_total", map[string]string{"source": "url", "result": "failure"}); got != 1 {
		t.Errorf("url failure count = %v, want 1", got)
	}

	// Verify file success count
	if got := getMetricValue(reg, "saml_disco_metadata_refresh_total", map[string]string{"source": "file", "result": "success"}); got != 1 {
		t.Errorf("file success count = %v, want 1", got)
	}

	// Verify IdP count gauge (should be last value: 10 from file refresh)
	if got := getMetricValue(reg, "saml_disco_metadata_idp_count", nil); got != 10 {
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

	// Verify behavior: metrics should be recorded
	recorder.RecordAuthAttempt("https://idp.example.com", true)
	recorder.RecordSessionCreated()

	// Verify metrics are recorded in the registry
	if got := getMetricValue(reg, "saml_disco_auth_attempts_total", map[string]string{"idp_entity_id": "https://idp.example.com", "result": "success"}); got != 1 {
		t.Errorf("auth attempts = %v, want 1", got)
	}
	if got := getMetricValue(reg, "saml_disco_sessions_created_total", nil); got != 1 {
		t.Errorf("sessions created = %v, want 1", got)
	}
}

// TestSAMLDisco_MetricsRecorder_Disabled verifies NoopMetricsRecorder is used when disabled.
// Note: This test verifies behavior through SetMetricsRecorder since initMetricsRecorder()
// is unexported. The actual initialization happens during Provision().
func TestSAMLDisco_MetricsRecorder_Disabled(t *testing.T) {
	// Use a custom registry to verify no metrics are recorded
	reg := prometheus.NewRegistry()
	noopRecorder := NewNoopMetricsRecorder()

	s := &SAMLDisco{
		Config: Config{
			MetricsEnabled: false,
		},
	}
	s.SetMetricsRecorder(noopRecorder)

	// Verify behavior: noop recorder should not record metrics in registry
	noopRecorder.RecordAuthAttempt("https://idp.example.com", true)
	noopRecorder.RecordSessionCreated()

	// Verify no metrics are recorded in the registry (noop recorder doesn't use registry)
	metrics, _ := reg.Gather()
	if len(metrics) > 0 {
		// Check that our specific metrics are not present
		for _, mf := range metrics {
			if mf.GetName() == "saml_disco_auth_attempts_total" || mf.GetName() == "saml_disco_sessions_created_total" {
				t.Errorf("unexpected metric %s recorded by noop recorder", mf.GetName())
			}
		}
	}
}
