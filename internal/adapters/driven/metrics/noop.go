package metrics

import (
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

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

// Ensure NoopMetricsRecorder implements ports.MetricsRecorder
var _ ports.MetricsRecorder = (*NoopMetricsRecorder)(nil)
