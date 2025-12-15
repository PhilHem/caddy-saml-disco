package caddysamldisco

import "github.com/prometheus/client_golang/prometheus"

// MetricsRecorder is the port interface for recording metrics.
// Implementations are adapters (PrometheusMetricsRecorder for production,
// NoopMetricsRecorder for disabled/testing).
type MetricsRecorder interface {
	// RecordAuthAttempt records a SAML authentication attempt.
	RecordAuthAttempt(idpEntityID string, success bool)

	// RecordSessionCreated records a new session creation.
	RecordSessionCreated()

	// RecordSessionValidation records a session validation result.
	RecordSessionValidation(valid bool)

	// RecordMetadataRefresh records a metadata refresh attempt.
	RecordMetadataRefresh(source string, success bool, idpCount int)
}

// NoopMetricsRecorder is a no-op implementation for when metrics are disabled.
// All methods are safe to call and do nothing.
type NoopMetricsRecorder struct{}

// NewNoopMetricsRecorder creates a new no-op metrics recorder.
func NewNoopMetricsRecorder() *NoopMetricsRecorder {
	return &NoopMetricsRecorder{}
}

// RecordAuthAttempt is a no-op.
func (n *NoopMetricsRecorder) RecordAuthAttempt(idpEntityID string, success bool) {}

// RecordSessionCreated is a no-op.
func (n *NoopMetricsRecorder) RecordSessionCreated() {}

// RecordSessionValidation is a no-op.
func (n *NoopMetricsRecorder) RecordSessionValidation(valid bool) {}

// RecordMetadataRefresh is a no-op.
func (n *NoopMetricsRecorder) RecordMetadataRefresh(source string, success bool, idpCount int) {}

// PrometheusMetricsRecorder records metrics using Prometheus.
type PrometheusMetricsRecorder struct {
	authAttemptsTotal       *prometheus.CounterVec
	sessionsCreatedTotal    prometheus.Counter
	sessionValidationsTotal *prometheus.CounterVec
	metadataRefreshTotal    *prometheus.CounterVec
	metadataIdpCount        prometheus.Gauge
}

// NewPrometheusMetricsRecorder creates a new Prometheus metrics recorder
// using the default Prometheus registry.
func NewPrometheusMetricsRecorder() *PrometheusMetricsRecorder {
	return NewPrometheusMetricsRecorderWithRegistry(prometheus.DefaultRegisterer)
}

// NewPrometheusMetricsRecorderWithRegistry creates a new Prometheus metrics recorder
// with a custom registry. Use this for testing.
func NewPrometheusMetricsRecorderWithRegistry(reg prometheus.Registerer) *PrometheusMetricsRecorder {
	authAttemptsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "saml_disco_auth_attempts_total",
		Help: "Total SAML authentication attempts",
	}, []string{"idp_entity_id", "result"})

	sessionsCreatedTotal := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "saml_disco_sessions_created_total",
		Help: "Total sessions created",
	})

	sessionValidationsTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "saml_disco_session_validations_total",
		Help: "Total session validation attempts",
	}, []string{"result"})

	metadataRefreshTotal := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "saml_disco_metadata_refresh_total",
		Help: "Total metadata refresh attempts",
	}, []string{"source", "result"})

	metadataIdpCount := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "saml_disco_metadata_idp_count",
		Help: "Current number of loaded IdPs",
	})

	reg.MustRegister(
		authAttemptsTotal,
		sessionsCreatedTotal,
		sessionValidationsTotal,
		metadataRefreshTotal,
		metadataIdpCount,
	)

	return &PrometheusMetricsRecorder{
		authAttemptsTotal:       authAttemptsTotal,
		sessionsCreatedTotal:    sessionsCreatedTotal,
		sessionValidationsTotal: sessionValidationsTotal,
		metadataRefreshTotal:    metadataRefreshTotal,
		metadataIdpCount:        metadataIdpCount,
	}
}

// RecordAuthAttempt records a SAML authentication attempt.
func (p *PrometheusMetricsRecorder) RecordAuthAttempt(idpEntityID string, success bool) {
	result := "failure"
	if success {
		result = "success"
	}
	p.authAttemptsTotal.WithLabelValues(idpEntityID, result).Inc()
}

// RecordSessionCreated records a new session creation.
func (p *PrometheusMetricsRecorder) RecordSessionCreated() {
	p.sessionsCreatedTotal.Inc()
}

// RecordSessionValidation records a session validation result.
func (p *PrometheusMetricsRecorder) RecordSessionValidation(valid bool) {
	result := "invalid"
	if valid {
		result = "valid"
	}
	p.sessionValidationsTotal.WithLabelValues(result).Inc()
}

// RecordMetadataRefresh records a metadata refresh attempt.
func (p *PrometheusMetricsRecorder) RecordMetadataRefresh(source string, success bool, idpCount int) {
	result := "failure"
	if success {
		result = "success"
	}
	p.metadataRefreshTotal.WithLabelValues(source, result).Inc()
	p.metadataIdpCount.Set(float64(idpCount))
}
