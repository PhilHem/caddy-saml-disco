package domain

import (
	"errors"
)

var (
	// ErrEntitlementNotFound is returned when a subject is not found in the entitlements store
	// and default_action is "deny".
	ErrEntitlementNotFound = errors.New("entitlement not found")

	// ErrAccessDenied is returned when access is denied by entitlements policy.
	ErrAccessDenied = errors.New("access denied by entitlements policy")
)

// DefaultAction determines behavior for subjects not in the entitlements file.
type DefaultAction string

const (
	// DefaultActionDeny means unlisted subjects are denied (allowlist mode).
	DefaultActionDeny DefaultAction = "deny"

	// DefaultActionAllow means unlisted subjects are allowed (blocklist mode).
	DefaultActionAllow DefaultAction = "allow"
)

// Entitlement represents access rights for a subject.
type Entitlement struct {
	// Subject is an exact match (mutually exclusive with Pattern).
	Subject string `json:"subject,omitempty"`

	// Pattern is a glob pattern for matching (mutually exclusive with Subject).
	// Supports: "*@example.edu", "staff@*", "*admin*", "exact@match.com"
	Pattern string `json:"pattern,omitempty"`

	// Roles are the roles assigned to this entitlement.
	Roles []string `json:"roles,omitempty"`

	// Metadata contains arbitrary key-value pairs for header injection.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// Validate checks that the entitlement is valid.
// Returns an error if both Subject and Pattern are set, or if neither is set.
func (e *Entitlement) Validate() error {
	hasSubject := e.Subject != ""
	hasPattern := e.Pattern != ""

	if hasSubject && hasPattern {
		return errors.New("entitlement cannot have both subject and pattern")
	}

	if !hasSubject && !hasPattern {
		return errors.New("entitlement must have either subject or pattern")
	}

	return nil
}

// EntitlementResult is the resolved entitlements for a lookup.
type EntitlementResult struct {
	// Roles are the roles assigned to the subject.
	Roles []string `json:"roles,omitempty"`

	// Metadata contains arbitrary key-value pairs.
	Metadata map[string]string `json:"metadata,omitempty"`

	// Matched is true if this was an explicit match, false if default_action=allow.
	Matched bool `json:"matched"`
}

// MatchesSubjectPattern checks if a subject matches a pattern.
// Reuses the existing MatchesEntityIDPattern logic for consistency.
func MatchesSubjectPattern(subject, pattern string) bool {
	return MatchesEntityIDPattern(subject, pattern)
}



