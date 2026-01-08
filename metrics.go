package caddysamldisco

import (
	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metrics"
	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// Re-export MetricsRecorder interface from ports
type MetricsRecorder = ports.MetricsRecorder

// Re-export metrics adapters
type NoopMetricsRecorder = metrics.NoopMetricsRecorder
type PrometheusMetricsRecorder = metrics.PrometheusMetricsRecorder

var (
	NewNoopMetricsRecorder                   = metrics.NewNoopMetricsRecorder
	NewPrometheusMetricsRecorder             = metrics.NewPrometheusMetricsRecorder
	NewPrometheusMetricsRecorderWithRegistry = metrics.NewPrometheusMetricsRecorderWithRegistry
)

// Re-export SAMLErrorCategory from domain
type SAMLErrorCategory = domain.SAMLErrorCategory

const (
	SAMLErrSignatureVerification = domain.SAMLErrSignatureVerification
	SAMLErrDecryptionFailed      = domain.SAMLErrDecryptionFailed
	SAMLErrTimeConstraint        = domain.SAMLErrTimeConstraint
	SAMLErrIdPStatus             = domain.SAMLErrIdPStatus
	SAMLErrUnknown               = domain.SAMLErrUnknown
)
