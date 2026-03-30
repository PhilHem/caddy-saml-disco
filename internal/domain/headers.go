package domain

// ASCIIToLower converts ASCII uppercase letters (A-Z) to lowercase (a-z).
// Non-ASCII characters are left unchanged.
//
// This is more appropriate for HTTP headers than strings.ToLower, which
// handles Unicode case folding that is not relevant for HTTP header names.
func ASCIIToLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		} else {
			b[i] = c
		}
	}
	return string(b)
}

// ASCIIEqualFold reports whether s and t are equal under ASCII case-folding.
// This is more appropriate for HTTP headers than strings.EqualFold, which
// handles Unicode case folding that is not relevant for HTTP header names.
//
// Per RFC 7230, HTTP header field names are case-insensitive and contain
// only ASCII characters.
func ASCIIEqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		cs := s[i]
		ct := t[i]
		// Convert both to lowercase if they're uppercase ASCII
		if cs >= 'A' && cs <= 'Z' {
			cs += 'a' - 'A'
		}
		if ct >= 'A' && ct <= 'Z' {
			ct += 'a' - 'A'
		}
		if cs != ct {
			return false
		}
	}
	return true
}
