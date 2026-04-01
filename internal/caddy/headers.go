package caddy

import (
	"net/http"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/httputil"
)

func shouldStripHeaders(spConfig *SPConfig) bool {
	if spConfig == nil || spConfig.StripAttributeHeaders == nil {
		return true
	}
	return *spConfig.StripAttributeHeaders
}

func (s *SAMLDisco) applyAttributeHeaders(r *http.Request, session *domain.Session, spConfig *SPConfig) {
	attributeHeaders := spConfig.attributeHeadersSnapshot
	if len(attributeHeaders) == 0 {
		attributeHeaders = spConfig.AttributeHeaders
	}
	entitlementHeaders := spConfig.entitlementHeadersSnapshot
	if len(entitlementHeaders) == 0 {
		entitlementHeaders = spConfig.EntitlementHeaders
	}
	headerPrefix := spConfig.headerPrefixSnapshot
	if headerPrefix == "" && spConfig.HeaderPrefix != "" {
		headerPrefix = spConfig.HeaderPrefix
	}
	cfg := httputil.HeaderConfig{
		AttributeHeaders:          attributeHeaders,
		EntitlementHeaders:        entitlementHeaders,
		HeaderPrefix:              headerPrefix,
		StripHeaders:              shouldStripHeaders(spConfig),
		EntitlementStore:          spConfig.entitlementStore,
		RestoreOnEntitlementError: true,
	}
	httputil.ApplyAttributeHeadersCore(r, session, cfg, s.getLogger())
}
