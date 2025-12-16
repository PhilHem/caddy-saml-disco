package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

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

// Ensure PrometheusMetricsRecorder implements ports.MetricsRecorder
var _ ports.MetricsRecorder = (*PrometheusMetricsRecorder)(nil)
