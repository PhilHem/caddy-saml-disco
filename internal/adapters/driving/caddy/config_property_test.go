//go:build unit

package caddy

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// Cycle 9: Property-Based Test - Configuration Validation

func TestSPConfigs_Property_AllValidWhenInstanceValid(t *testing.T) {
	f := func(configs []Config) bool {
		// Skip empty configs
		if len(configs) == 0 {
			return true
		}

		spConfigs := make([]*SPConfig, len(configs))
		for i := range configs {
			spConfigs[i] = &SPConfig{
				Hostname: fmt.Sprintf("app%d.example.com", i),
				Config:   configs[i],
			}
		}

		// If instance validates successfully, all configs should be valid
		err := validateSPConfigs(spConfigs)
		if err != nil {
			// If validation fails, at least one config should be invalid OR there's a duplicate cookie name
			allValid := true
			for _, cfg := range spConfigs {
				if cfg.Validate() != nil {
					allValid = false
					break
				}
			}
			if allValid {
				// All configs are valid but validation failed - check for duplicate cookie names
				cookieNames := make(map[string]int)
				for _, cfg := range spConfigs {
					cookieName := cfg.SessionCookieName
					if cookieName == "" {
						cookieName = "saml_session" // default
					}
					cookieNames[cookieName]++
				}
				hasDuplicates := false
				for _, count := range cookieNames {
					if count > 1 {
						hasDuplicates = true
						break
					}
				}
				// If no duplicates, this is a bug
				return hasDuplicates
			}
			return true // Found invalid config, validation failure expected
		}

		// If validation succeeds, all configs must be valid
		for _, cfg := range spConfigs {
			if cfg.Validate() != nil {
				return false // Found invalid config in valid instance
			}
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestSPConfigs_Property_UniqueCookieNames(t *testing.T) {
	f := func(configs []Config) bool {
		if len(configs) == 0 {
			return true
		}

		spConfigs := make([]*SPConfig, len(configs))
		cookieNames := make(map[string]int)

		for i := range configs {
			spConfigs[i] = &SPConfig{
				Hostname: fmt.Sprintf("app%d.example.com", i),
				Config:   configs[i],
			}
			cookieName := spConfigs[i].SessionCookieName
			if cookieName == "" {
				cookieName = "saml_session" // default
			}
			cookieNames[cookieName]++
		}

		// Check for duplicates
		hasDuplicates := false
		for _, count := range cookieNames {
			if count > 1 {
				hasDuplicates = true
				break
			}
		}

		err := validateSPConfigs(spConfigs)

		// Property: validation should fail if duplicates exist
		return (err != nil) == hasDuplicates
	}

	// Custom generator to create configs with controlled cookie names
	config := &quick.Config{
		Values: func(values []reflect.Value, r *rand.Rand) {
			numConfigs := 1 + r.Intn(5)
			configs := make([]Config, numConfigs)
			for i := range configs {
				configs[i] = Config{
					EntityID:         fmt.Sprintf("https://sp%d/saml", i),
					MetadataFile:     "/path/to/metadata.xml",
					CertFile:         "/path/to/cert.pem",
					KeyFile:          "/path/to/key.pem",
					SessionCookieName: fmt.Sprintf("cookie_%d", r.Intn(3)), // 0-2, so duplicates possible
				}
			}
			values[0] = reflect.ValueOf(configs)
		},
	}

	if err := quick.Check(f, config); err != nil {
		t.Error(err)
	}
}






