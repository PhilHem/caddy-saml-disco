package entitlements

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/philiph/caddy-saml-disco/internal/core/domain"
	"github.com/philiph/caddy-saml-disco/internal/core/ports"
)

// FileEntitlementStore loads entitlements from a local JSON or YAML file.
type FileEntitlementStore struct {
	path   string
	logger *zap.Logger

	mu             sync.RWMutex
	defaultAction  domain.DefaultAction
	exactMatches   map[string]domain.Entitlement
	patternMatches []domain.Entitlement
}

// EntitlementsFile represents the structure of the entitlements file.
type EntitlementsFile struct {
	DefaultAction string               `json:"default_action" yaml:"default_action"`
	Entries       []domain.Entitlement `json:"entries" yaml:"entries"`
}

// NewFileEntitlementStore creates a new file-based entitlement store.
func NewFileEntitlementStore(path string, logger *zap.Logger) *FileEntitlementStore {
	return &FileEntitlementStore{
		path:          path,
		logger:        logger,
		defaultAction: domain.DefaultActionDeny,
		exactMatches:  make(map[string]domain.Entitlement),
	}
}

// Lookup returns entitlements for a subject.
func (s *FileEntitlementStore) Lookup(subject string) (*domain.EntitlementResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check exact matches first
	if e, ok := s.exactMatches[subject]; ok {
		return &domain.EntitlementResult{
			Roles:    e.Roles,
			Metadata: e.Metadata,
			Matched:  true,
		}, nil
	}

	// Check pattern matches
	for _, e := range s.patternMatches {
		if domain.MatchesSubjectPattern(subject, e.Pattern) {
			return &domain.EntitlementResult{
				Roles:    e.Roles,
				Metadata: e.Metadata,
				Matched:  true,
			}, nil
		}
	}

	// No match - apply default action
	if s.defaultAction == domain.DefaultActionDeny {
		return nil, domain.ErrEntitlementNotFound
	}

	return &domain.EntitlementResult{Matched: false}, nil
}

// Refresh reloads entitlements from the file.
func (s *FileEntitlementStore) Refresh(ctx context.Context) error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("read entitlements file: %w", err)
	}

	var file EntitlementsFile
	ext := strings.ToLower(filepath.Ext(s.path))
	if ext == ".yaml" || ext == ".yml" {
		if err := yaml.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("parse YAML entitlements file: %w", err)
		}
	} else {
		if err := json.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("parse JSON entitlements file: %w", err)
		}
	}

	// Validate default action
	defaultAction := domain.DefaultAction(file.DefaultAction)
	if defaultAction != domain.DefaultActionDeny && defaultAction != domain.DefaultActionAllow {
		if file.DefaultAction == "" {
			defaultAction = domain.DefaultActionDeny // default
		} else {
			return fmt.Errorf("invalid default_action %q, must be 'deny' or 'allow'", file.DefaultAction)
		}
	}

	// Validate and organize entitlements
	exactMatches := make(map[string]domain.Entitlement)
	var patternMatches []domain.Entitlement

	for _, e := range file.Entries {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("invalid entitlement: %w", err)
		}

		if e.Subject != "" {
			exactMatches[e.Subject] = e
		} else if e.Pattern != "" {
			patternMatches = append(patternMatches, e)
		}
	}

	// Atomic update
	s.mu.Lock()
	s.defaultAction = defaultAction
	s.exactMatches = exactMatches
	s.patternMatches = patternMatches
	s.mu.Unlock()

	return nil
}

// Ensure FileEntitlementStore implements ports.EntitlementStore
var _ ports.EntitlementStore = (*FileEntitlementStore)(nil)






