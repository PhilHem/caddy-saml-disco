package domain

// CombinedAttributes represents the merged result of SAML attributes and local entitlements.
// Local entitlements supplement (not replace) IdP-provided SAML attributes.
type CombinedAttributes struct {
	// SAMLAttributes are the attributes from the IdP SAML assertion.
	SAMLAttributes map[string][]string

	// Roles are the roles from local entitlements.
	Roles []string

	// Metadata contains arbitrary key-value pairs from local entitlements.
	Metadata map[string]string
}

// CombineAttributes merges SAML attributes with local entitlements.
// Local entitlements supplement IdP-provided attributes.
// Returns a CombinedAttributes struct with all data preserved.
func CombineAttributes(saml map[string][]string, local *EntitlementResult) CombinedAttributes {
	result := CombinedAttributes{
		SAMLAttributes: make(map[string][]string),
		Roles:          nil,
		Metadata:       make(map[string]string),
	}

	// Copy SAML attributes
	if saml != nil {
		for k, v := range saml {
			// Deep copy the slice
			result.SAMLAttributes[k] = make([]string, len(v))
			copy(result.SAMLAttributes[k], v)
		}
	}

	// Copy local entitlements
	if local != nil {
		// Copy roles
		if local.Roles != nil {
			result.Roles = make([]string, len(local.Roles))
			copy(result.Roles, local.Roles)
		}

		// Copy metadata
		if local.Metadata != nil {
			for k, v := range local.Metadata {
				result.Metadata[k] = v
			}
		}
	}

	return result
}
