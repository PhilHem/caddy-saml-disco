package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/core/ports"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metrics"
)

// Re-export MetricsRecorder interface from ports
type MetricsRecorder = ports.MetricsRecorder

// Re-export metrics adapters
type NoopMetricsRecorder = metrics.NoopMetricsRecorder
type PrometheusMetricsRecorder = metrics.PrometheusMetricsRecorder

var (
	NewNoopMetricsRecorder                = metrics.NewNoopMetricsRecorder
	NewPrometheusMetricsRecorder          = metrics.NewPrometheusMetricsRecorder
	NewPrometheusMetricsRecorderWithRegistry = metrics.NewPrometheusMetricsRecorderWithRegistry
)
