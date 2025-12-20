package ports

// CachedLogo represents a cached IdP logo with its binary data.
type CachedLogo struct {
	Data        []byte
	ContentType string
}

// LogoStore defines the interface for fetching and caching IdP logos.
type LogoStore interface {
	Get(entityID string) (*CachedLogo, error)
}






