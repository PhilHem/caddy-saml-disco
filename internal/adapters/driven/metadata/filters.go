package metadata

import (
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// filterEmptyStrings removes empty strings from a slice.
func filterEmptyStrings(ss []string) []string {
	var result []string
	for _, s := range ss {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

// parseCSVPatterns parses a comma-separated pattern string into a slice of trimmed, non-empty patterns.
// Returns nil if input is empty or contains only empty/whitespace patterns.
func parseCSVPatterns(pattern string) []string {
	if pattern == "" {
		return nil
	}
	patterns := strings.Split(pattern, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}
	patterns = filterEmptyStrings(patterns)
	if len(patterns) == 0 {
		return nil
	}
	return patterns
}

// filterIdPsByField filters IdPs by a string field using pattern matching.
// The fieldAccessor extracts the string field value from an IdP.
// IdPs with empty field values are excluded when a filter is active.
func filterIdPsByField(idps []domain.IdPInfo, pattern string, fieldAccessor func(domain.IdPInfo) string) []domain.IdPInfo {
	if pattern == "" {
		return idps
	}

	patterns := parseCSVPatterns(pattern)
	if patterns == nil {
		return nil
	}

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		fieldValue := fieldAccessor(idp)
		if fieldValue == "" {
			continue
		}
		for _, p := range patterns {
			if domain.MatchesEntityIDPattern(fieldValue, p) {
				filtered = append(filtered, idp)
				break
			}
		}
	}
	return filtered
}

// filterIdPsBySliceField filters IdPs by a slice field using exact matching.
// The fieldAccessor extracts the slice field values from an IdP.
// IdPs with empty/nil field values are excluded when a filter is active.
func filterIdPsBySliceField(idps []domain.IdPInfo, pattern string, fieldAccessor func(domain.IdPInfo) []string) []domain.IdPInfo {
	if pattern == "" {
		return idps
	}

	patterns := parseCSVPatterns(pattern)
	if patterns == nil {
		return nil
	}

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		fieldValues := fieldAccessor(idp)
		if len(fieldValues) == 0 {
			continue
		}
		hasMatch := false
		for _, requiredVal := range patterns {
			for _, idpVal := range fieldValues {
				if idpVal == requiredVal {
					hasMatch = true
					break
				}
			}
			if hasMatch {
				break
			}
		}
		if hasMatch {
			filtered = append(filtered, idp)
		}
	}
	return filtered
}

// filterIdPs returns only IdPs whose entity ID matches the pattern.
// Supports comma-separated patterns (OR logic - IdP must match at least one).
func filterIdPs(idps []domain.IdPInfo, pattern string) []domain.IdPInfo {
	if pattern == "" {
		return idps
	}

	patterns := parseCSVPatterns(pattern)
	if patterns == nil {
		return nil
	}

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		for _, p := range patterns {
			if domain.MatchesEntityIDPattern(idp.EntityID, p) {
				filtered = append(filtered, idp)
				break
			}
		}
	}
	return filtered
}

// FilterIdPsByRegistrationAuthority returns only IdPs whose registration authority
// matches the pattern. Supports comma-separated patterns for multiple authorities.
// IdPs without a registration authority are excluded when a filter is active.
func FilterIdPsByRegistrationAuthority(idps []domain.IdPInfo, pattern string) []domain.IdPInfo {
	return filterIdPsByField(idps, pattern, func(idp domain.IdPInfo) string {
		return idp.RegistrationAuthority
	})
}

// FilterIdPsByEntityCategory returns only IdPs that have at least one of the specified entity categories.
// Supports comma-separated categories (OR logic - IdP must have at least one).
// IdPs without any entity categories are excluded when a filter is active.
func FilterIdPsByEntityCategory(idps []domain.IdPInfo, categories string) []domain.IdPInfo {
	return filterIdPsBySliceField(idps, categories, func(idp domain.IdPInfo) []string {
		return idp.EntityCategories
	})
}

// FilterIdPsByAssuranceCertification returns only IdPs that have at least one of the specified assurance certifications.
// Supports comma-separated certifications (OR logic - IdP must have at least one).
// IdPs without any assurance certifications are excluded when a filter is active.
func FilterIdPsByAssuranceCertification(idps []domain.IdPInfo, certifications string) []domain.IdPInfo {
	return filterIdPsBySliceField(idps, certifications, func(idp domain.IdPInfo) []string {
		return idp.AssuranceCertifications
	})
}
