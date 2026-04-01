package discovery

import (
	"sort"
	"strconv"
	"strings"

	"github.com/philiph/caddy-saml-disco/internal/domain"
)

// localizeIdPList applies localization to a slice of IdPInfo based on
// language preferences.
func localizeIdPList(idps []domain.IdPInfo, prefs []string, defaultLang string) []domain.IdPInfo {
	if len(idps) == 0 {
		return idps
	}
	localized := make([]domain.IdPInfo, len(idps))
	for i, idp := range idps {
		localized[i] = domain.LocalizeIdPInfo(idp, prefs, defaultLang)
	}
	return localized
}

// ParseAcceptLanguage parses the Accept-Language header and returns
// language tags sorted by quality value (highest first).
// For language tags with region (e.g., "en-US"), the base language
// is also included (e.g., "en") as a fallback.
func ParseAcceptLanguage(header string) []string {
	if header == "" {
		return []string{}
	}

	type langQ struct {
		lang string
		q    float64
	}

	var langs []langQ

	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		lang := part
		q := 1.0

		if idx := strings.Index(part, ";"); idx != -1 {
			lang = strings.TrimSpace(part[:idx])
			qPart := strings.TrimSpace(part[idx+1:])
			if strings.HasPrefix(qPart, "q=") {
				if parsed, err := strconv.ParseFloat(qPart[2:], 64); err == nil {
					q = parsed
				}
			}
		}

		if lang == "" {
			continue
		}

		if q > 0 {
			langs = append(langs, langQ{lang: lang, q: q})
			// Add base language for regional variants (en-US -> en)
			if idx := strings.Index(lang, "-"); idx != -1 {
				base := lang[:idx]
				langs = append(langs, langQ{lang: base, q: q - 0.0001})
			}
		}
	}

	sort.Slice(langs, func(i, j int) bool {
		return langs[i].q > langs[j].q
	})

	// Deduplicate while preserving order
	seen := make(map[string]bool)
	result := []string{}
	for _, lq := range langs {
		if !seen[lq.lang] {
			seen[lq.lang] = true
			result = append(result, lq.lang)
		}
	}

	return result
}
