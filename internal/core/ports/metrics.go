package ports

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



