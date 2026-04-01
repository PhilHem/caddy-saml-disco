package caddy

import (
	"context"
	"fmt"
	"time"

	"github.com/philiph/caddy-saml-disco/internal/config"
	"github.com/philiph/caddy-saml-disco/internal/discovery"
	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
	"github.com/philiph/caddy-saml-disco/internal/ports"
	samlsvc "github.com/philiph/caddy-saml-disco/internal/saml"
)

type SPConfig struct {
	config.SPConfig
	metadataStore              ports.MetadataStore
	sessionStore               ports.SessionStore
	entitlementStore           ports.EntitlementStore
	logoStore                  ports.LogoStore
	samlService                *samlsvc.SAMLService
	sessionDuration            time.Duration
	templateRenderer           *discovery.TemplateRenderer
	headerPrefixSnapshot       string
	attributeHeadersSnapshot   []domain.AttributeMapping
	entitlementHeadersSnapshot []httputil.EntitlementHeaderMapping
	entitlementRefreshCancel   context.CancelFunc
}

func (c *SPConfig) Validate() error {
	if c.Hostname == "" {
		return fmt.Errorf("hostname is required")
	}
	return c.Config.Validate()
}

func (c *SPConfig) snapshotConfig() {
	c.headerPrefixSnapshot = c.HeaderPrefix
	c.attributeHeadersSnapshot = make([]domain.AttributeMapping, len(c.AttributeHeaders))
	copy(c.attributeHeadersSnapshot, c.AttributeHeaders)
	c.entitlementHeadersSnapshot = make([]httputil.EntitlementHeaderMapping, len(c.EntitlementHeaders))
	copy(c.entitlementHeadersSnapshot, c.EntitlementHeaders)
}

func validateSPConfigs(configs []*SPConfig) error {
	cookieNames := make(map[string]string)
	for _, cfg := range configs {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("sp config for %s: %w", cfg.Hostname, err)
		}
		cookieName := cfg.Config.SessionCookieName
		if cookieName == "" {
			cookieName = "saml_session"
		}
		if existingHost := cookieNames[cookieName]; existingHost != "" {
			return fmt.Errorf("duplicate session_cookie_name %q used by %s and %s",
				cookieName, existingHost, cfg.Hostname)
		}
		cookieNames[cookieName] = cfg.Hostname
	}
	return nil
}
