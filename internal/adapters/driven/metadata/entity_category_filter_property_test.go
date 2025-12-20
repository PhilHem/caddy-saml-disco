//go:build unit

package metadata

import (
	"strings"
	"testing"
	"testing/quick"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// Property: Filtered result is always a subset of input
func TestFilterIdPsByEntityCategory_Property_Subset(t *testing.T) {
	f := func(categories string, idpCount int) bool {
		if idpCount < 0 || idpCount > 100 {
			return true // skip unreasonable sizes
		}

		// Generate test IdPs
		idps := make([]domain.IdPInfo, idpCount)
		for i := range idps {
			idps[i] = domain.IdPInfo{
				EntityID:       domain.IdPInfo{}.EntityID, // Use zero value
				EntityCategories: []string{"http://refeds.org/category/research-and-scholarship"},
			}
			idps[i].EntityID = "https://idp" + string(rune(i)) + ".example.com"
		}

		filtered := FilterIdPsByEntityCategory(idps, categories)

		// Property: Filtered is subset - every filtered IdP must be in original
		for _, filteredIdp := range filtered {
			found := false
			for _, originalIdp := range idps {
				if originalIdp.EntityID == filteredIdp.EntityID {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Property: Empty filter returns all IdPs
func TestFilterIdPsByEntityCategory_Property_EmptyFilter(t *testing.T) {
	f := func(idpCount int) bool {
		if idpCount < 0 || idpCount > 100 {
			return true // skip unreasonable sizes
		}

		idps := make([]domain.IdPInfo, idpCount)
		for i := range idps {
			idps[i] = domain.IdPInfo{
				EntityID: "https://idp" + string(rune(i)) + ".example.com",
			}
		}

		filtered := FilterIdPsByEntityCategory(idps, "")

		// Property: Empty filter returns all
		return len(filtered) == len(idps)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Property: All filtered IdPs contain at least one required category
func TestFilterIdPsByEntityCategory_Property_AllHaveCategory(t *testing.T) {
	f := func(categories string) bool {
		if categories == "" {
			return true // skip empty filter
		}

		// Parse required categories
		requiredCats := strings.Split(categories, ",")
		for i := range requiredCats {
			requiredCats[i] = strings.TrimSpace(requiredCats[i])
		}

		// Create IdPs with various categories
		idps := []domain.IdPInfo{
			{EntityID: "idp1", EntityCategories: []string{"http://refeds.org/category/research-and-scholarship"}},
			{EntityID: "idp2", EntityCategories: []string{"https://refeds.org/category/code-of-conduct/v2"}},
			{EntityID: "idp3", EntityCategories: []string{"http://refeds.org/category/research-and-scholarship", "https://refeds.org/category/code-of-conduct/v2"}},
			{EntityID: "idp4", EntityCategories: nil},
		}

		filtered := FilterIdPsByEntityCategory(idps, categories)

		// Property: All filtered IdPs have at least one required category
		for _, idp := range filtered {
			if len(idp.EntityCategories) == 0 {
				return false // Should not include IdPs without categories
			}
			hasMatch := false
			for _, requiredCat := range requiredCats {
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
			if !hasMatch {
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Property: Filtering by assurance certification has same properties
func TestFilterIdPsByAssuranceCertification_Property_Subset(t *testing.T) {
	f := func(certifications string, idpCount int) bool {
		if idpCount < 0 || idpCount > 100 {
			return true // skip unreasonable sizes
		}

		idps := make([]domain.IdPInfo, idpCount)
		for i := range idps {
			idps[i] = domain.IdPInfo{
				EntityID:                "https://idp" + string(rune(i)) + ".example.com",
				AssuranceCertifications: []string{"https://refeds.org/sirtfi"},
			}
		}

		filtered := FilterIdPsByAssuranceCertification(idps, certifications)

		// Property: Filtered is subset
		for _, filteredIdp := range filtered {
			found := false
			for _, originalIdp := range idps {
				if originalIdp.EntityID == filteredIdp.EntityID {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// Property: Empty assurance certification filter returns all IdPs
func TestFilterIdPsByAssuranceCertification_Property_EmptyFilter(t *testing.T) {
	f := func(idpCount int) bool {
		if idpCount < 0 || idpCount > 100 {
			return true // skip unreasonable sizes
		}

		idps := make([]domain.IdPInfo, idpCount)
		for i := range idps {
			idps[i] = domain.IdPInfo{
				EntityID: "https://idp" + string(rune(i)) + ".example.com",
			}
		}

		filtered := FilterIdPsByAssuranceCertification(idps, "")

		// Property: Empty filter returns all
		return len(filtered) == len(idps)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}



