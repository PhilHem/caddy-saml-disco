//go:build unit

package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// TestNoopMetricsRecorder_Interface verifies the interface contract.
func TestNoopMetricsRecorder_Interface(t *testing.T) {
	var _ ports.MetricsRecorder = (*NoopMetricsRecorder)(nil)
}

// TestNoopMetricsRecorder_AllMethods verifies all methods don't panic.
func TestNoopMetricsRecorder_AllMethods(t *testing.T) {
	recorder := NewNoopMetricsRecorder()

	// None of these should panic
	recorder.RecordAuthAttempt("https://idp.example.com", true)
	recorder.RecordAuthAttempt("https://idp.example.com", false)
	recorder.RecordSessionCreated()
	recorder.RecordSessionValidation(true)
	recorder.RecordSessionValidation(false)
	recorder.RecordMetadataRefresh("url", true, 10)
	recorder.RecordMetadataRefresh("file", false, 0)
}

// TestPrometheusMetricsRecorder_Interface verifies the interface contract.
func TestPrometheusMetricsRecorder_Interface(t *testing.T) {
	var _ ports.MetricsRecorder = (*PrometheusMetricsRecorder)(nil)
}

// TestPrometheusMetricsRecorder_RecordAuthAttempt verifies auth attempt recording.
func TestPrometheusMetricsRecorder_RecordAuthAttempt(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder := NewPrometheusMetricsRecorderWithRegistry(registry)

	// Record success and failure
	recorder.RecordAuthAttempt("https://idp1.example.com", true)
	recorder.RecordAuthAttempt("https://idp1.example.com", false)
	recorder.RecordAuthAttempt("https://idp2.example.com", true)

	// Gather metrics
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Find the auth attempts metric
	var authMetric *io_prometheus_client.MetricFamily
	for _, mf := range metricFamilies {
		if mf.GetName() == "saml_disco_auth_attempts_total" {
			authMetric = mf
			break
		}
	}

	if authMetric == nil {
		t.Fatal("saml_disco_auth_attempts_total metric not found")
	}

	// Check we have 3 metrics (2 for idp1, 1 for idp2)
	if len(authMetric.GetMetric()) != 3 {
		t.Errorf("expected 3 metric entries, got %d", len(authMetric.GetMetric()))
	}

	// Verify counter values
	for _, m := range authMetric.GetMetric() {
		var idp, result string
		for _, label := range m.GetLabel() {
			switch label.GetName() {
			case "idp_entity_id":
				idp = label.GetValue()
			case "result":
				result = label.GetValue()
			}
		}

		value := m.GetCounter().GetValue()
		if idp == "https://idp1.example.com" && result == "success" && value != 1 {
			t.Errorf("idp1 success count = %v, want 1", value)
		}
		if idp == "https://idp1.example.com" && result == "failure" && value != 1 {
			t.Errorf("idp1 failure count = %v, want 1", value)
		}
		if idp == "https://idp2.example.com" && result == "success" && value != 1 {
			t.Errorf("idp2 success count = %v, want 1", value)
		}
	}
}

// TestPrometheusMetricsRecorder_RecordSessionCreated verifies session creation recording.
func TestPrometheusMetricsRecorder_RecordSessionCreated(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder := NewPrometheusMetricsRecorderWithRegistry(registry)

	// Record multiple session creations
	recorder.RecordSessionCreated()
	recorder.RecordSessionCreated()
	recorder.RecordSessionCreated()

	// Gather metrics
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Find the session created metric
	var sessionMetric *io_prometheus_client.MetricFamily
	for _, mf := range metricFamilies {
		if mf.GetName() == "saml_disco_sessions_created_total" {
			sessionMetric = mf
			break
		}
	}

	if sessionMetric == nil {
		t.Fatal("saml_disco_sessions_created_total metric not found")
	}

	// Check counter value
	if len(sessionMetric.GetMetric()) != 1 {
		t.Fatalf("expected 1 metric entry, got %d", len(sessionMetric.GetMetric()))
	}

	value := sessionMetric.GetMetric()[0].GetCounter().GetValue()
	if value != 3 {
		t.Errorf("sessions created count = %v, want 3", value)
	}
}

// TestPrometheusMetricsRecorder_RecordSessionValidation verifies session validation recording.
func TestPrometheusMetricsRecorder_RecordSessionValidation(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder := NewPrometheusMetricsRecorderWithRegistry(registry)

	// Record valid and invalid validations
	recorder.RecordSessionValidation(true)
	recorder.RecordSessionValidation(true)
	recorder.RecordSessionValidation(false)

	// Gather metrics
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Find the session validation metric
	var validationMetric *io_prometheus_client.MetricFamily
	for _, mf := range metricFamilies {
		if mf.GetName() == "saml_disco_session_validations_total" {
			validationMetric = mf
			break
		}
	}

	if validationMetric == nil {
		t.Fatal("saml_disco_session_validations_total metric not found")
	}

	// Check we have 2 metrics (valid and invalid)
	if len(validationMetric.GetMetric()) != 2 {
		t.Errorf("expected 2 metric entries, got %d", len(validationMetric.GetMetric()))
	}

	// Verify counter values
	for _, m := range validationMetric.GetMetric() {
		var result string
		for _, label := range m.GetLabel() {
			if label.GetName() == "result" {
				result = label.GetValue()
			}
		}

		value := m.GetCounter().GetValue()
		if result == "valid" && value != 2 {
			t.Errorf("valid count = %v, want 2", value)
		}
		if result == "invalid" && value != 1 {
			t.Errorf("invalid count = %v, want 1", value)
		}
	}
}

// TestPrometheusMetricsRecorder_RecordMetadataRefresh verifies metadata refresh recording.
func TestPrometheusMetricsRecorder_RecordMetadataRefresh(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder := NewPrometheusMetricsRecorderWithRegistry(registry)

	// Record metadata refreshes
	recorder.RecordMetadataRefresh("url", true, 100)
	recorder.RecordMetadataRefresh("url", false, 0)
	recorder.RecordMetadataRefresh("file", true, 50)

	// Gather metrics
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Find the metadata refresh metric
	var refreshMetric *io_prometheus_client.MetricFamily
	var idpCountMetric *io_prometheus_client.MetricFamily
	for _, mf := range metricFamilies {
		switch mf.GetName() {
		case "saml_disco_metadata_refresh_total":
			refreshMetric = mf
		case "saml_disco_metadata_idp_count":
			idpCountMetric = mf
		}
	}

	if refreshMetric == nil {
		t.Fatal("saml_disco_metadata_refresh_total metric not found")
	}
	if idpCountMetric == nil {
		t.Fatal("saml_disco_metadata_idp_count metric not found")
	}

	// Check we have 3 metrics (url success, url failure, file success)
	if len(refreshMetric.GetMetric()) != 3 {
		t.Errorf("expected 3 metric entries, got %d", len(refreshMetric.GetMetric()))
	}

	// Check IdP count gauge (should be last value set = 50)
	if len(idpCountMetric.GetMetric()) != 1 {
		t.Fatalf("expected 1 gauge entry, got %d", len(idpCountMetric.GetMetric()))
	}

	idpCount := idpCountMetric.GetMetric()[0].GetGauge().GetValue()
	if idpCount != 50 {
		t.Errorf("idp_count gauge = %v, want 50", idpCount)
	}
}
