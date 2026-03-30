//go:build unit

package caddy

import (
	"fmt"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// Cycle 3: Property-Based Test - Routing Correctness

func TestSPConfigRegistry_Property_RoutingCorrectness(t *testing.T) {
	f := func(hostnames []string, lookupHostname string) bool {
		if len(hostnames) == 0 {
			return true // Skip empty configs
		}

		registry := NewSPConfigRegistry()
		for i, hostname := range hostnames {
			// Skip empty hostnames
			if hostname == "" {
				continue
			}
			cfg := &SPConfig{
				Hostname: hostname,
				Config: Config{
					EntityID: fmt.Sprintf("https://sp%d/saml", i),
				},
			}
			registry.Add(cfg)
		}

		found := registry.GetByHostname(lookupHostname)

		// Property: found != nil iff lookupHostname is in hostnames
		expectedFound := false
		for _, h := range hostnames {
			if h == lookupHostname {
				expectedFound = true
				break
			}
		}

		return (found != nil) == expectedFound
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestSPConfigRegistry_Property_RoutingCorrectness_CustomGenerator(t *testing.T) {
	f := func(hostnames []string, lookupHostname string) bool {
		if len(hostnames) == 0 {
			return true // Skip empty configs
		}

		registry := NewSPConfigRegistry()
		for i, hostname := range hostnames {
			// Skip empty hostnames
			if hostname == "" {
				continue
			}
			cfg := &SPConfig{
				Hostname: hostname,
				Config: Config{
					EntityID: fmt.Sprintf("https://sp%d/saml", i),
				},
			}
			registry.Add(cfg)
		}

		found := registry.GetByHostname(lookupHostname)

		// Property: found != nil iff lookupHostname is in hostnames
		expectedFound := false
		for _, h := range hostnames {
			if h == lookupHostname {
				expectedFound = true
				break
			}
		}

		return (found != nil) == expectedFound
	}

	// Custom generator to create reasonable hostname strings
	config := &quick.Config{
		Values: func(values []reflect.Value, r *rand.Rand) {
			// Generate 1-5 hostnames
			numHostnames := 1 + r.Intn(5)
			hostnames := make([]string, numHostnames)
			for i := 0; i < numHostnames; i++ {
				// Generate simple hostname: "app%d.example.com"
				hostnames[i] = fmt.Sprintf("app%d.example.com", i)
			}
			values[0] = reflect.ValueOf(hostnames)

			// Generate lookup hostname (may or may not be in the list)
			if r.Intn(2) == 0 {
				// 50% chance to pick from existing hostnames
				values[1] = reflect.ValueOf(hostnames[r.Intn(len(hostnames))])
			} else {
				// 50% chance to pick a new hostname
				values[1] = reflect.ValueOf(fmt.Sprintf("unknown%d.example.com", r.Intn(100)))
			}
		},
	}

	if err := quick.Check(f, config); err != nil {
		t.Error(err)
	}
}
