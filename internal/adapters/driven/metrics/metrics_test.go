//go:build unit

package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	io_prometheus_client "github.com/prometheus/client_model/go"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
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

	// New auth metrics methods - use .String() since interface takes string
	recorder.RecordAuthFailure(domain.SAMLErrSignatureVerification.String(), "https://idp.example.com")
	recorder.RecordAuthFailure(domain.SAMLErrUnknown.String(), "")
	recorder.RecordAuthSuccess("https://idp.example.com")
	recorder.RecordAuthDuration("https://idp.example.com", "success", 100*time.Millisecond)
	recorder.RecordAuthDuration("https://idp.example.com", "failure", 50*time.Millisecond)
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

// TestPrometheusMetricsRecorder_RecordAuthFailure verifies auth failure recording with category.
func TestPrometheusMetricsRecorder_RecordAuthFailure(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder := NewPrometheusMetricsRecorderWithRegistry(registry)

	// Record failures with different categories
	recorder.RecordAuthFailure(domain.SAMLErrSignatureVerification.String(), "https://idp1.example.com")
	recorder.RecordAuthFailure(domain.SAMLErrTimeConstraint.String(), "https://idp1.example.com")
	recorder.RecordAuthFailure(domain.SAMLErrSignatureVerification.String(), "https://idp2.example.com")

	// Gather metrics
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Find the auth failures metric
	var failureMetric *io_prometheus_client.MetricFamily
	for _, mf := range metricFamilies {
		if mf.GetName() == "saml_disco_auth_failures_total" {
			failureMetric = mf
			break
		}
	}

	if failureMetric == nil {
		t.Fatal("saml_disco_auth_failures_total metric not found")
	}

	// Check we have 3 metric entries (different label combinations)
	if len(failureMetric.GetMetric()) != 3 {
		t.Errorf("expected 3 metric entries, got %d", len(failureMetric.GetMetric()))
	}

	// Verify counter values and labels
	for _, m := range failureMetric.GetMetric() {
		var reason, idp string
		for _, label := range m.GetLabel() {
			switch label.GetName() {
			case "reason":
				reason = label.GetValue()
			case "idp":
				idp = label.GetValue()
			}
		}

		value := m.GetCounter().GetValue()
		if idp == "https://idp1.example.com" && reason == domain.SAMLErrSignatureVerification.String() && value != 1 {
			t.Errorf("idp1 signature_verification count = %v, want 1", value)
		}
		if idp == "https://idp1.example.com" && reason == domain.SAMLErrTimeConstraint.String() && value != 1 {
			t.Errorf("idp1 time_constraint count = %v, want 1", value)
		}
		if idp == "https://idp2.example.com" && reason == domain.SAMLErrSignatureVerification.String() && value != 1 {
			t.Errorf("idp2 signature_verification count = %v, want 1", value)
		}
	}
}

// TestPrometheusMetricsRecorder_RecordAuthSuccess verifies successful auth recording.
func TestPrometheusMetricsRecorder_RecordAuthSuccess(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder := NewPrometheusMetricsRecorderWithRegistry(registry)

	// Record successes for different IdPs
	recorder.RecordAuthSuccess("https://idp1.example.com")
	recorder.RecordAuthSuccess("https://idp1.example.com")
	recorder.RecordAuthSuccess("https://idp2.example.com")

	// Gather metrics
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Find the auth success metric
	var successMetric *io_prometheus_client.MetricFamily
	for _, mf := range metricFamilies {
		if mf.GetName() == "saml_disco_auth_success_total" {
			successMetric = mf
			break
		}
	}

	if successMetric == nil {
		t.Fatal("saml_disco_auth_success_total metric not found")
	}

	// Check we have 2 metric entries (one per IdP)
	if len(successMetric.GetMetric()) != 2 {
		t.Errorf("expected 2 metric entries, got %d", len(successMetric.GetMetric()))
	}

	// Verify counter values
	for _, m := range successMetric.GetMetric() {
		var idp string
		for _, label := range m.GetLabel() {
			if label.GetName() == "idp" {
				idp = label.GetValue()
			}
		}

		value := m.GetCounter().GetValue()
		if idp == "https://idp1.example.com" && value != 2 {
			t.Errorf("idp1 success count = %v, want 2", value)
		}
		if idp == "https://idp2.example.com" && value != 1 {
			t.Errorf("idp2 success count = %v, want 1", value)
		}
	}
}

// TestPrometheusMetricsRecorder_RecordAuthDuration verifies auth duration histogram recording.
func TestPrometheusMetricsRecorder_RecordAuthDuration(t *testing.T) {
	registry := prometheus.NewRegistry()
	recorder := NewPrometheusMetricsRecorderWithRegistry(registry)

	// Record durations for different IdPs and outcomes
	recorder.RecordAuthDuration("https://idp1.example.com", "success", 100*time.Millisecond)
	recorder.RecordAuthDuration("https://idp1.example.com", "success", 200*time.Millisecond)
	recorder.RecordAuthDuration("https://idp1.example.com", "failure", 50*time.Millisecond)
	recorder.RecordAuthDuration("https://idp2.example.com", "success", 150*time.Millisecond)

	// Gather metrics
	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}

	// Find the auth duration metric
	var durationMetric *io_prometheus_client.MetricFamily
	for _, mf := range metricFamilies {
		if mf.GetName() == "saml_disco_auth_duration_seconds" {
			durationMetric = mf
			break
		}
	}

	if durationMetric == nil {
		t.Fatal("saml_disco_auth_duration_seconds metric not found")
	}

	// Check we have 3 metric entries (different label combinations)
	if len(durationMetric.GetMetric()) != 3 {
		t.Errorf("expected 3 metric entries, got %d", len(durationMetric.GetMetric()))
	}

	// Verify histogram values
	for _, m := range durationMetric.GetMetric() {
		var idp, outcome string
		for _, label := range m.GetLabel() {
			switch label.GetName() {
			case "idp":
				idp = label.GetValue()
			case "outcome":
				outcome = label.GetValue()
			}
		}

		hist := m.GetHistogram()
		count := hist.GetSampleCount()
		sum := hist.GetSampleSum()

		if idp == "https://idp1.example.com" && outcome == "success" {
			if count != 2 {
				t.Errorf("idp1 success count = %v, want 2", count)
			}
			// Sum should be approximately 0.3s (100ms + 200ms)
			if sum < 0.29 || sum > 0.31 {
				t.Errorf("idp1 success sum = %v, want ~0.3", sum)
			}
		}
		if idp == "https://idp1.example.com" && outcome == "failure" {
			if count != 1 {
				t.Errorf("idp1 failure count = %v, want 1", count)
			}
		}
		if idp == "https://idp2.example.com" && outcome == "success" {
			if count != 1 {
				t.Errorf("idp2 success count = %v, want 1", count)
			}
		}
	}
}
