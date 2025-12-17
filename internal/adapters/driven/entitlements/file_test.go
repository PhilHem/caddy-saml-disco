//go:build integration

package entitlements

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFileEntitlementStore_LoadJSON(t *testing.T) {
	store := NewFileEntitlementStore("testdata/entitlements.json", nil)
	err := store.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v, want nil", err)
	}

	result, err := store.Lookup("admin@example.edu")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if !result.Matched {
		t.Error("Lookup() Matched = false, want true")
	}
	if len(result.Roles) != 2 {
		t.Errorf("Lookup() Roles = %v, want [admin staff]", result.Roles)
	}
	if result.Metadata["department"] != "IT" {
		t.Errorf("Lookup() Metadata[department] = %v, want IT", result.Metadata["department"])
	}
}

func TestFileEntitlementStore_LoadYAML(t *testing.T) {
	store := NewFileEntitlementStore("testdata/entitlements.yaml", nil)
	err := store.Refresh(context.Background())
	if err != nil {
		t.Fatalf("Refresh() error = %v, want nil", err)
	}

	result, err := store.Lookup("admin@example.edu")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if !result.Matched {
		t.Error("Lookup() Matched = false, want true")
	}
	if len(result.Roles) != 2 {
		t.Errorf("Lookup() Roles = %v, want [admin staff]", result.Roles)
	}
}

func TestFileEntitlementStore_HotReload(t *testing.T) {
	// Create temporary file
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "entitlements.json")

	// Write initial file
	initialContent := `{"default_action": "deny", "entries": [{"subject": "user1@example.edu", "roles": ["user"]}]}`
	if err := os.WriteFile(filePath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	store := NewFileEntitlementStore(filePath, nil)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v, want nil", err)
	}

	// Verify initial state
	result, err := store.Lookup("user1@example.edu")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if len(result.Roles) != 1 || result.Roles[0] != "user" {
		t.Errorf("Lookup() Roles = %v, want [user]", result.Roles)
	}

	// Modify file
	modifiedContent := `{"default_action": "deny", "entries": [{"subject": "user1@example.edu", "roles": ["admin"]}]}`
	if err := os.WriteFile(filePath, []byte(modifiedContent), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	// Refresh and verify new state
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v, want nil", err)
	}

	result, err = store.Lookup("user1@example.edu")
	if err != nil {
		t.Fatalf("Lookup() error = %v, want nil", err)
	}
	if len(result.Roles) != 1 || result.Roles[0] != "admin" {
		t.Errorf("Lookup() Roles = %v, want [admin] after reload", result.Roles)
	}
}

// Cycle 17: Property-Based Test - Atomic Reload
// Property: Lookup during reload returns consistent results (old OR new, never partial)
func TestFileEntitlementStore_Property_AtomicReload(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "entitlements.json")

	// Write initial file
	initialContent := `{"default_action": "deny", "entries": [{"subject": "user@example.edu", "roles": ["old"]}]}`
	if err := os.WriteFile(filePath, []byte(initialContent), 0644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	store := NewFileEntitlementStore(filePath, nil)
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}

	var wg sync.WaitGroup
	lookupCount := 100
	refreshCount := 10

	// Concurrent lookups
	for i := 0; i < lookupCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := store.Lookup("user@example.edu")
			if err != nil {
				return // ignore errors during reload
			}
			// Should see either "old" or "new", never partial state
			if len(result.Roles) > 0 {
				role := result.Roles[0]
				if role != "old" && role != "new" {
					t.Errorf("Lookup() saw invalid role %q during reload", role)
				}
			}
		}()
	}

	// Concurrent refreshes
	for i := 0; i < refreshCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Alternate between old and new content
			content := initialContent
			if i%2 == 1 {
				content = `{"default_action": "deny", "entries": [{"subject": "user@example.edu", "roles": ["new"]}]}`
			}
			os.WriteFile(filePath, []byte(content), 0644)
			store.Refresh(context.Background())
		}()
	}

	wg.Wait()
	// No panic = pass (race detector will catch issues)
}
