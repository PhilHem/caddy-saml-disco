package domain

import "strings"

// oidRegistry maps OIDs to their friendly names and vice versa.
// This is a pure domain component with no external dependencies.
var oidRegistry = map[string]string{
	// eduPerson attributes
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.6":  "eduPersonPrincipalName",
	"eduPersonPrincipalName":            "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.7":  "eduPersonEntitlement",
	"eduPersonEntitlement":              "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.9":  "eduPersonScopedAffiliation",
	"eduPersonScopedAffiliation":        "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.10": "eduPersonTargetedID",
	"eduPersonTargetedID":               "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",

	// Standard LDAP attributes
	"urn:oid:0.9.2342.19200300.100.1.3": "mail",
	"mail":                              "urn:oid:0.9.2342.19200300.100.1.3",
	"urn:oid:2.5.4.42":                  "givenName",
	"givenName":                         "urn:oid:2.5.4.42",
	"urn:oid:2.5.4.4":                   "sn",
	"sn":                                "urn:oid:2.5.4.4",
	"urn:oid:2.16.840.1.113730.3.1.241": "displayName",
	"displayName":                       "urn:oid:2.16.840.1.113730.3.1.241",

	// SCHAC attributes
	"urn:oid:1.3.6.1.4.1.25178.1.2.9": "schacHomeOrganization",
	"schacHomeOrganization":           "urn:oid:1.3.6.1.4.1.25178.1.2.9",
}

// ResolveAttributeName resolves a SAML attribute name to both its OID and friendly name.
// If the input is a known OID, returns the OID and its friendly name.
// If the input is a known friendly name, returns the OID and friendly name.
// If the input is unknown, returns it unchanged for both OID and friendly name.
//
// This is a pure function with no side effects or I/O.
func ResolveAttributeName(name string) (oid, friendlyName string) {
	if name == "" {
		return "", ""
	}

	// Check if it's a known OID or friendly name
	if resolved, ok := oidRegistry[name]; ok {
		// If name is an OID, resolved is the friendly name
		if strings.HasPrefix(name, "urn:oid:") {
			return name, resolved
		}
		// If name is a friendly name, resolved is the OID
		return resolved, name
	}

	// Unknown name passes through unchanged
	return name, name
}

// scopedAttributes is the set of attribute names that are scoped (have @scope format).
// These attributes must have their scope validated against IdP metadata.
var scopedAttributes = map[string]bool{
	"eduPersonPrincipalName":           true,
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.6": true, // eduPersonPrincipalName OID
	"eduPersonScopedAffiliation":       true,
	"urn:oid:1.3.6.1.4.1.5923.1.1.1.9": true, // eduPersonScopedAffiliation OID
}

// IsScopedAttribute returns true if the attribute name is a scoped attribute.
// Scoped attributes have values in the format "user@scope" and must be validated
// against the IdP's allowed scopes from shibmd:Scope metadata.
//
// This is a pure function with no side effects or I/O.
func IsScopedAttribute(name string) bool {
	if name == "" {
		return false
	}
	return scopedAttributes[name]
}



