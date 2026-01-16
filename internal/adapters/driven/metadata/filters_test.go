package metadata

import (
	"testing"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
)

// TestFilterIdPs_Basic tests the basic filterIdPs function with various pattern types.
// @tra: Adapter.Metadata.FilterPatterns
func TestFilterIdPs_Basic(t *testing.T) {
	tests := []struct {
		name     string
		idps     []domain.IdPInfo
		pattern  string
		expected []string // EntityIDs of expected results
	}{
		{
			name:     "empty pattern returns all",
			pattern:  "",
			idps:     []domain.IdPInfo{{EntityID: "idp1"}, {EntityID: "idp2"}},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:     "no match returns empty",
			pattern:  "nonexistent",
			idps:     []domain.IdPInfo{{EntityID: "idp1"}, {EntityID: "idp2"}},
			expected: []string{},
		},
		{
			name:     "exact match",
			pattern:  "idp1",
			idps:     []domain.IdPInfo{{EntityID: "idp1"}, {EntityID: "idp2"}},
			expected: []string{"idp1"},
		},
		{
			name:     "prefix pattern",
			pattern:  "https://example.com*",
			idps:     []domain.IdPInfo{{EntityID: "https://example.com/idp1"}, {EntityID: "https://other.com/idp"}},
			expected: []string{"https://example.com/idp1"},
		},
		{
			name:     "suffix pattern",
			pattern:  "*example.com",
			idps:     []domain.IdPInfo{{EntityID: "https://example.com"}, {EntityID: "https://other.com"}},
			expected: []string{"https://example.com"},
		},
		{
			name:     "substring pattern",
			pattern:  "*example*",
			idps:     []domain.IdPInfo{{EntityID: "https://example.com/idp"}, {EntityID: "https://test.com"}},
			expected: []string{"https://example.com/idp"},
		},
		{
			name:     "wildcard returns all",
			pattern:  "*",
			idps:     []domain.IdPInfo{{EntityID: "idp1"}, {EntityID: "idp2"}},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:     "empty IdP list",
			pattern:  "test",
			idps:     []domain.IdPInfo{},
			expected: []string{},
		},
		{
			name:     "multiple matches",
			pattern:  "https://*",
			idps:     []domain.IdPInfo{{EntityID: "https://idp1.com"}, {EntityID: "https://idp2.com"}, {EntityID: "http://idp3.com"}},
			expected: []string{"https://idp1.com", "https://idp2.com"},
		},
		{
			name:     "case-sensitive matching",
			pattern:  "Test",
			idps:     []domain.IdPInfo{{EntityID: "test"}, {EntityID: "Test"}},
			expected: []string{"Test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterIdPs(tt.idps, tt.pattern)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d results, got %d", len(tt.expected), len(result))
			}
			for i, expected := range tt.expected {
				if i >= len(result) || result[i].EntityID != expected {
					t.Errorf("expected EntityID %q at index %d, got %q", expected, i,
						func() string {
							if i >= len(result) {
								return "<missing>"
							}
							return result[i].EntityID
						}())
				}
			}
		})
	}
}

// TestFilterIdPsByRegistrationAuthority tests filtering by registration authority with various patterns.
// @tra: Adapter.Metadata.FilterRegistrationAuthority
func TestFilterIdPsByRegistrationAuthority(t *testing.T) {
	tests := []struct {
		name     string
		idps     []domain.IdPInfo
		pattern  string
		expected []string // EntityIDs of expected results
	}{
		{
			name:     "empty pattern returns all",
			pattern:  "",
			idps:     []domain.IdPInfo{{EntityID: "idp1", RegistrationAuthority: "fed1"}},
			expected: []string{"idp1"},
		},
		{
			name:    "single authority exact match",
			pattern: "federation1",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "federation1"},
				{EntityID: "idp2", RegistrationAuthority: "federation2"},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "multiple authorities with comma separation",
			pattern: "fed1, fed2",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "fed1"},
				{EntityID: "idp2", RegistrationAuthority: "fed2"},
				{EntityID: "idp3", RegistrationAuthority: "fed3"},
			},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:    "IdPs without registration authority are excluded",
			pattern: "fed1",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "fed1"},
				{EntityID: "idp2", RegistrationAuthority: ""},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "prefix pattern matching",
			pattern: "https://registry*",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "https://registry.example.com"},
				{EntityID: "idp2", RegistrationAuthority: "https://other.com"},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "suffix pattern matching",
			pattern: "*.example.com",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "registry.example.com"},
				{EntityID: "idp2", RegistrationAuthority: "example.com"},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "no matches",
			pattern: "nonexistent",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "fed1"},
			},
			expected: []string{},
		},
		{
			name:    "trailing whitespace in pattern",
			pattern: "fed1  ,  fed2  ",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "fed1"},
				{EntityID: "idp2", RegistrationAuthority: "fed2"},
			},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:    "empty IdP list",
			pattern: "fed1",
			idps:    []domain.IdPInfo{},
			expected: []string{},
		},
		{
			name:    "complex URI patterns",
			pattern: "https://www.aai.dfn.de, https://incommon.org",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "https://www.aai.dfn.de"},
				{EntityID: "idp2", RegistrationAuthority: "https://incommon.org"},
				{EntityID: "idp3", RegistrationAuthority: "https://other.org"},
			},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:    "substring matching in registration authority",
			pattern: "*dfn*",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "https://www.aai.dfn.de"},
				{EntityID: "idp2", RegistrationAuthority: "https://other.org"},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "only empty patterns after trim",
			pattern: ", , ",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", RegistrationAuthority: "fed1"},
			},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterIdPsByRegistrationAuthority(tt.idps, tt.pattern)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d results, got %d", len(tt.expected), len(result))
			}
			for i, expected := range tt.expected {
				if i >= len(result) || result[i].EntityID != expected {
					t.Errorf("expected EntityID %q at index %d, got %q", expected, i,
						func() string {
							if i >= len(result) {
								return "<missing>"
							}
							return result[i].EntityID
						}())
				}
			}
		})
	}
}

// TestFilterIdPsByEntityCategory tests filtering by entity categories with OR logic.
// @tra: Adapter.Metadata.FilterEntityCategory
func TestFilterIdPsByEntityCategory(t *testing.T) {
	tests := []struct {
		name     string
		idps     []domain.IdPInfo
		pattern  string
		expected []string // EntityIDs of expected results
	}{
		{
			name:     "empty pattern returns all",
			pattern:  "",
			idps:     []domain.IdPInfo{{EntityID: "idp1", EntityCategories: []string{"cat1"}}},
			expected: []string{"idp1"},
		},
		{
			name:    "single category match",
			pattern: "research",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: []string{"research"}},
				{EntityID: "idp2", EntityCategories: []string{"commercial"}},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "multiple categories with OR logic",
			pattern: "research, commercial",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: []string{"research"}},
				{EntityID: "idp2", EntityCategories: []string{"commercial"}},
				{EntityID: "idp3", EntityCategories: []string{"government"}},
			},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:    "IdP with multiple categories, one matches",
			pattern: "commercial",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: []string{"research", "commercial"}},
				{EntityID: "idp2", EntityCategories: []string{"government"}},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "IdPs without categories are excluded",
			pattern: "research",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: []string{"research"}},
				{EntityID: "idp2", EntityCategories: []string{}},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "no matches",
			pattern: "nonexistent",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: []string{"research"}},
			},
			expected: []string{},
		},
		{
			name:    "whitespace handling in categories",
			pattern: "research  ,  commercial  ",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: []string{"research"}},
				{EntityID: "idp2", EntityCategories: []string{"commercial"}},
			},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:    "nil categories list",
			pattern: "research",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: nil},
			},
			expected: []string{},
		},
		{
			name:    "empty IdP list",
			pattern: "research",
			idps:    []domain.IdPInfo{},
			expected: []string{},
		},
		{
			name:    "only empty patterns after trim",
			pattern: ", , ",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: []string{"cat1"}},
			},
			expected: []string{},
		},
		{
			name:    "category with URIs",
			pattern: "http://www.geant.net/uri/nren-category/nren",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", EntityCategories: []string{"http://www.geant.net/uri/nren-category/nren"}},
				{EntityID: "idp2", EntityCategories: []string{"http://other.org/category"}},
			},
			expected: []string{"idp1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterIdPsByEntityCategory(tt.idps, tt.pattern)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d results, got %d", len(tt.expected), len(result))
			}
			for i, expected := range tt.expected {
				if i >= len(result) || result[i].EntityID != expected {
					t.Errorf("expected EntityID %q at index %d, got %q", expected, i,
						func() string {
							if i >= len(result) {
								return "<missing>"
							}
							return result[i].EntityID
						}())
				}
			}
		})
	}
}

// TestFilterIdPsByAssuranceCertification tests filtering by assurance certifications.
// @tra: Adapter.Metadata.FilterAssuranceCertification
func TestFilterIdPsByAssuranceCertification(t *testing.T) {
	tests := []struct {
		name     string
		idps     []domain.IdPInfo
		pattern  string
		expected []string // EntityIDs of expected results
	}{
		{
			name:     "empty pattern returns all",
			pattern:  "",
			idps:     []domain.IdPInfo{{EntityID: "idp1", AssuranceCertifications: []string{"sirtfi"}}},
			expected: []string{"idp1"},
		},
		{
			name:    "single certification match",
			pattern: "sirtfi",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: []string{"sirtfi"}},
				{EntityID: "idp2", AssuranceCertifications: []string{"other"}},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "multiple certifications with OR logic",
			pattern: "sirtfi, loc",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: []string{"sirtfi"}},
				{EntityID: "idp2", AssuranceCertifications: []string{"loc"}},
				{EntityID: "idp3", AssuranceCertifications: []string{"other"}},
			},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:    "IdP with multiple certifications, one matches",
			pattern: "loc",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: []string{"sirtfi", "loc"}},
				{EntityID: "idp2", AssuranceCertifications: []string{"sirtfi"}},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "IdPs without certifications are excluded",
			pattern: "sirtfi",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: []string{"sirtfi"}},
				{EntityID: "idp2", AssuranceCertifications: []string{}},
			},
			expected: []string{"idp1"},
		},
		{
			name:    "no matches",
			pattern: "nonexistent",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: []string{"sirtfi"}},
			},
			expected: []string{},
		},
		{
			name:    "whitespace handling",
			pattern: "sirtfi  ,  loc  ",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: []string{"sirtfi"}},
				{EntityID: "idp2", AssuranceCertifications: []string{"loc"}},
			},
			expected: []string{"idp1", "idp2"},
		},
		{
			name:    "nil certifications list",
			pattern: "sirtfi",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: nil},
			},
			expected: []string{},
		},
		{
			name:    "empty IdP list",
			pattern: "sirtfi",
			idps:    []domain.IdPInfo{},
			expected: []string{},
		},
		{
			name:    "only empty patterns after trim",
			pattern: ", , ",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: []string{"cert1"}},
			},
			expected: []string{},
		},
		{
			name:    "certification with URIs",
			pattern: "https://refeds.org/sirtfi",
			idps: []domain.IdPInfo{
				{EntityID: "idp1", AssuranceCertifications: []string{"https://refeds.org/sirtfi"}},
				{EntityID: "idp2", AssuranceCertifications: []string{"https://other.org/cert"}},
			},
			expected: []string{"idp1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FilterIdPsByAssuranceCertification(tt.idps, tt.pattern)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d results, got %d", len(tt.expected), len(result))
			}
			for i, expected := range tt.expected {
				if i >= len(result) || result[i].EntityID != expected {
					t.Errorf("expected EntityID %q at index %d, got %q", expected, i,
						func() string {
							if i >= len(result) {
								return "<missing>"
							}
							return result[i].EntityID
						}())
				}
			}
		})
	}
}

// TestFilterIdPs_EdgeCases tests edge cases and boundary conditions across all filters.
// @tra: Adapter.Metadata.FilterEdgeCases
func TestFilterIdPs_EdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{
			name: "filterEmptyStrings removes all empty strings",
			testFunc: func(t *testing.T) {
				result := filterEmptyStrings([]string{"a", "", "b", "", "c"})
				if len(result) != 3 {
					t.Errorf("expected 3 results, got %d", len(result))
				}
				expected := []string{"a", "b", "c"}
				for i, exp := range expected {
					if result[i] != exp {
						t.Errorf("expected %q at index %d, got %q", exp, i, result[i])
					}
				}
			},
		},
		{
			name: "filterEmptyStrings handles all empty strings",
			testFunc: func(t *testing.T) {
				result := filterEmptyStrings([]string{"", "", ""})
				if len(result) != 0 {
					t.Errorf("expected 0 results, got %d", len(result))
				}
			},
		},
		{
			name: "filterEmptyStrings handles empty input",
			testFunc: func(t *testing.T) {
				result := filterEmptyStrings([]string{})
				if len(result) != 0 {
					t.Errorf("expected 0 results, got %d", len(result))
				}
			},
		},
		{
			name: "FilterIdPsByRegistrationAuthority with only empty patterns",
			testFunc: func(t *testing.T) {
				idps := []domain.IdPInfo{
					{EntityID: "idp1", RegistrationAuthority: "fed1"},
				}
				result := FilterIdPsByRegistrationAuthority(idps, ", , ")
				if len(result) != 0 {
					t.Errorf("expected 0 results, got %d", len(result))
				}
			},
		},
		{
			name: "FilterIdPsByEntityCategory with only empty patterns",
			testFunc: func(t *testing.T) {
				idps := []domain.IdPInfo{
					{EntityID: "idp1", EntityCategories: []string{"cat1"}},
				}
				result := FilterIdPsByEntityCategory(idps, ", , ")
				if len(result) != 0 {
					t.Errorf("expected 0 results, got %d", len(result))
				}
			},
		},
		{
			name: "FilterIdPsByAssuranceCertification with only empty patterns",
			testFunc: func(t *testing.T) {
				idps := []domain.IdPInfo{
					{EntityID: "idp1", AssuranceCertifications: []string{"cert1"}},
				}
				result := FilterIdPsByAssuranceCertification(idps, ", , ")
				if len(result) != 0 {
					t.Errorf("expected 0 results, got %d", len(result))
				}
			},
		},
		{
			name: "large number of IdPs with registration authority",
			testFunc: func(t *testing.T) {
				idps := make([]domain.IdPInfo, 1000)
				for i := 0; i < 1000; i++ {
					idps[i].EntityID = "idp" + string(rune(i%26+97))
					idps[i].RegistrationAuthority = "fed" + string(rune(i%10+48))
				}
				result := FilterIdPsByRegistrationAuthority(idps, "fed5")
				if len(result) < 90 || len(result) > 110 {
					t.Errorf("expected ~100 results, got %d", len(result))
				}
			},
		},
		{
			name: "special characters in patterns",
			testFunc: func(t *testing.T) {
				idps := []domain.IdPInfo{
					{EntityID: "https://example.com/idp", RegistrationAuthority: "urn:federation:example"},
				}
				result := FilterIdPsByRegistrationAuthority(idps, "urn:federation:*")
				if len(result) != 1 {
					t.Errorf("expected 1 result, got %d", len(result))
				}
			},
		},
		{
			name: "case sensitivity in exact matches",
			testFunc: func(t *testing.T) {
				idps := []domain.IdPInfo{
					{EntityID: "idp1", RegistrationAuthority: "FED1"},
				}
				result := FilterIdPsByRegistrationAuthority(idps, "fed1")
				if len(result) != 0 {
					t.Errorf("expected 0 results (case-sensitive), got %d", len(result))
				}
			},
		},
		{
			name: "pattern with trailing comma",
			testFunc: func(t *testing.T) {
				idps := []domain.IdPInfo{
					{EntityID: "idp1", RegistrationAuthority: "fed1"},
					{EntityID: "idp2", RegistrationAuthority: "fed2"},
				}
				result := FilterIdPsByRegistrationAuthority(idps, "fed1,")
				if len(result) != 1 {
					t.Errorf("expected 1 result, got %d", len(result))
				}
			},
		},
		{
			name: "pattern with leading comma",
			testFunc: func(t *testing.T) {
				idps := []domain.IdPInfo{
					{EntityID: "idp1", RegistrationAuthority: "fed1"},
					{EntityID: "idp2", RegistrationAuthority: "fed2"},
				}
				result := FilterIdPsByRegistrationAuthority(idps, ",fed1")
				if len(result) != 1 {
					t.Errorf("expected 1 result, got %d", len(result))
				}
			},
		},
		{
			name: "filterIdPs with case sensitivity",
			testFunc: func(t *testing.T) {
				idps := []domain.IdPInfo{
					{EntityID: "https://EXAMPLE.COM"},
					{EntityID: "https://example.com"},
				}
				result := filterIdPs(idps, "https://example.com")
				if len(result) != 1 || result[0].EntityID != "https://example.com" {
					t.Errorf("expected exact case match, got %v", result)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.testFunc(t)
		})
	}
}
