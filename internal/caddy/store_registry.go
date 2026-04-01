package caddy

import (
	"github.com/philiph/caddy-saml-disco/internal/caddy/internal/sharedstate"
	"github.com/philiph/caddy-saml-disco/internal/config"
	"github.com/philiph/caddy-saml-disco/internal/metrics"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

func getSharedRequestStore() ports.RequestStore { return sharedstate.GetSharedRequestStore() }

func (s *SAMLDisco) defaultSPConfig() *SPConfig {
	if s.registry == nil {
		s.registry = NewSPConfigRegistry()
	}
	sp := s.registry.GetByHostname("")
	if sp == nil {
		sp = &SPConfig{SPConfig: config.SPConfig{Config: s.Config}}
		_ = s.registry.Add(sp) // error only if wildcard exists, which we just checked
	}
	return sp
}

func (s *SAMLDisco) getMetricsRecorder() ports.MetricsRecorder {
	if s.metricsRecorder != nil { return s.metricsRecorder }
	return metrics.NewNoopMetricsRecorder()
}

func (s *SAMLDisco) initMetricsRecorder() {
	if s.MetricsEnabled {
		s.metricsRecorder = metrics.NewPrometheusMetricsRecorder()
	} else {
		s.metricsRecorder = metrics.NewNoopMetricsRecorder()
	}
}
