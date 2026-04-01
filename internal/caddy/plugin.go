package caddy

import (
	"fmt"
	"net/http"
	"sync"

	"go.uber.org/zap"

	"github.com/philiph/caddy-saml-disco/internal/domain"
	"github.com/philiph/caddy-saml-disco/internal/ports"
)

type HealthResponse struct {
	Version   string `json:"version"`
	GitCommit string `json:"git_commit,omitempty"`
	BuildTime string `json:"build_time,omitempty"`
	domain.MetadataHealth
}

type sessionContextKey struct{}

func GetSession(r *http.Request) *domain.Session {
	session, _ := r.Context().Value(sessionContextKey{}).(*domain.Session)
	return session
}

// SAMLDisco is a Caddy HTTP handler providing SAML SP authentication with IdP discovery.
type SAMLDisco struct {
	Config    // single-SP mode; normalized to SPConfigs during Provision
	SPConfigs []*SPConfig `json:"sp_configs,omitempty"`

	registry        *SPConfigRegistry
	logger          *zap.Logger
	metricsRecorder ports.MetricsRecorder
}

type SPConfigRegistry struct {
	configs map[string]*SPConfig
	mu      sync.RWMutex
}

func NewSPConfigRegistry() *SPConfigRegistry {
	return &SPConfigRegistry{
		configs: make(map[string]*SPConfig),
	}
}

func (r *SPConfigRegistry) Add(cfg *SPConfig) error {
	if cfg == nil {
		return fmt.Errorf("config cannot be nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.configs[cfg.Hostname]; exists {
		if cfg.Hostname == "" {
			return fmt.Errorf("wildcard SP config already exists")
		}
		return fmt.Errorf("SP config with hostname %q already exists", cfg.Hostname)
	}
	r.configs[cfg.Hostname] = cfg
	return nil
}

func (r *SPConfigRegistry) GetByHostname(hostname string) *SPConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if cfg, ok := r.configs[hostname]; ok {
		return cfg
	}
	return r.configs[""]
}

func (r *SPConfigRegistry) AllConfigs() []*SPConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	configs := make([]*SPConfig, 0, len(r.configs))
	for _, cfg := range r.configs {
		configs = append(configs, cfg)
	}
	return configs
}

var (
	versionSetOnce sync.Once
	getVersion     = func() string { return "dev" }
	getGitCommit   = func() string { return "" }
	getBuildTime   = func() string { return "" }
)

func SetVersionGetters(version, gitCommit, buildTime func() string) {
	versionSetOnce.Do(func() {
		getVersion = version
		getGitCommit = gitCommit
		getBuildTime = buildTime
	})
}
