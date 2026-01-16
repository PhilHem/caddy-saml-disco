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

// filterIdPs returns only IdPs whose entity ID matches the pattern.
// Supports comma-separated patterns (OR logic - IdP must match at least one).
func filterIdPs(idps []domain.IdPInfo, pattern string) []domain.IdPInfo {
	if pattern == "" {
		return idps
	}

	// Parse comma-separated patterns
	patterns := strings.Split(pattern, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}

	// Filter out empty patterns
	patterns = filterEmptyStrings(patterns)

	// If all patterns were empty, return no matches
	if len(patterns) == 0 {
		return nil
	}

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		// Check if entity ID matches any pattern
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
	if pattern == "" {
		return idps
	}

	// Parse comma-separated patterns
	patterns := strings.Split(pattern, ",")
	for i := range patterns {
		patterns[i] = strings.TrimSpace(patterns[i])
	}

	// Filter out empty patterns (METADATA-012: empty pattern matches everything)
	patterns = filterEmptyStrings(patterns)

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		// Skip IdPs without a registration authority
		if idp.RegistrationAuthority == "" {
			continue
		}
		// Check if registration authority matches any pattern
		for _, p := range patterns {
			if domain.MatchesEntityIDPattern(idp.RegistrationAuthority, p) {
				filtered = append(filtered, idp)
				break
			}
		}
	}
	return filtered
}

// FilterIdPsByEntityCategory returns only IdPs that have at least one of the specified entity categories.
// Supports comma-separated categories (OR logic - IdP must have at least one).
// IdPs without any entity categories are excluded when a filter is active.
func FilterIdPsByEntityCategory(idps []domain.IdPInfo, categories string) []domain.IdPInfo {
	if categories == "" {
		return idps
	}

	// Parse comma-separated categories
	categoryList := strings.Split(categories, ",")
	for i := range categoryList {
		categoryList[i] = strings.TrimSpace(categoryList[i])
	}

	// Filter out empty strings (METADATA-013: empty strings never match but are processed)
	categoryList = filterEmptyStrings(categoryList)

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		// Skip IdPs without any categories
		if len(idp.EntityCategories) == 0 {
			continue
		}
		// Check if IdP has at least one of the required categories
		hasMatch := false
		for _, requiredCat := range categoryList {
			for _, idpCat := range idp.EntityCategories {
				if idpCat == requiredCat {
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

// FilterIdPsByAssuranceCertification returns only IdPs that have at least one of the specified assurance certifications.
// Supports comma-separated certifications (OR logic - IdP must have at least one).
// IdPs without any assurance certifications are excluded when a filter is active.
func FilterIdPsByAssuranceCertification(idps []domain.IdPInfo, certifications string) []domain.IdPInfo {
	if certifications == "" {
		return idps
	}

	// Parse comma-separated certifications
	certList := strings.Split(certifications, ",")
	for i := range certList {
		certList[i] = strings.TrimSpace(certList[i])
	}

	// Filter out empty strings (METADATA-013: empty strings never match but are processed)
	certList = filterEmptyStrings(certList)

	var filtered []domain.IdPInfo
	for _, idp := range idps {
		// Skip IdPs without any certifications
		if len(idp.AssuranceCertifications) == 0 {
			continue
		}
		// Check if IdP has at least one of the required certifications
		hasMatch := false
		for _, requiredCert := range certList {
			for _, idpCert := range idp.AssuranceCertifications {
				if idpCert == requiredCert {
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
