//go:build unit

package domain

import (
	"testing"
)

func TestSeparatePinnedIdPs(t *testing.T) {
	idps := []IdPInfo{
		{EntityID: "https://idp1.example.com"},
		{EntityID: "https://idp2.example.com"},
		{EntityID: "https://idp3.example.com"},
		{EntityID: "https://idp4.example.com"},
	}

	tests := []struct {
		name               string
		pinnedEntityIDs    []string
		wantPinnedCount    int
		wantRemainingCount int
		wantPinnedOrder    []string
	}{
		{
			name:               "no pinned",
			pinnedEntityIDs:    nil,
			wantPinnedCount:    0,
			wantRemainingCount: 4,
		},
		{
			name:               "empty pinned",
			pinnedEntityIDs:    []string{},
			wantPinnedCount:    0,
			wantRemainingCount: 4,
		},
		{
			name:               "one pinned",
			pinnedEntityIDs:    []string{"https://idp2.example.com"},
			wantPinnedCount:    1,
			wantRemainingCount: 3,
			wantPinnedOrder:    []string{"https://idp2.example.com"},
		},
		{
			name:               "multiple pinned in order",
			pinnedEntityIDs:    []string{"https://idp3.example.com", "https://idp1.example.com"},
			wantPinnedCount:    2,
			wantRemainingCount: 2,
			wantPinnedOrder:    []string{"https://idp3.example.com", "https://idp1.example.com"},
		},
		{
			name:               "pinned entity not in list",
			pinnedEntityIDs:    []string{"https://idp-nonexistent.example.com"},
			wantPinnedCount:    0,
			wantRemainingCount: 4,
		},
		{
			name:               "all pinned",
			pinnedEntityIDs:    []string{"https://idp1.example.com", "https://idp2.example.com", "https://idp3.example.com", "https://idp4.example.com"},
			wantPinnedCount:    4,
			wantRemainingCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pinned, remaining := SeparatePinnedIdPs(idps, tc.pinnedEntityIDs)

			if len(pinned) != tc.wantPinnedCount {
				t.Errorf("pinned count = %d, want %d", len(pinned), tc.wantPinnedCount)
			}
			if len(remaining) != tc.wantRemainingCount {
				t.Errorf("remaining count = %d, want %d", len(remaining), tc.wantRemainingCount)
			}

			// Verify pinned order
			if tc.wantPinnedOrder != nil {
				for i, entityID := range tc.wantPinnedOrder {
					if i < len(pinned) && pinned[i].EntityID != entityID {
						t.Errorf("pinned[%d].EntityID = %q, want %q", i, pinned[i].EntityID, entityID)
					}
				}
			}

			// Verify pinned is never nil
			if pinned == nil {
				t.Error("pinned should not be nil")
			}
			// Verify remaining is never nil
			if remaining == nil {
				t.Error("remaining should not be nil")
			}
		})
	}
}

func TestSeparatePinnedIdPs_EmptyInput(t *testing.T) {
	pinned, remaining := SeparatePinnedIdPs(nil, []string{"https://idp1.example.com"})

	if len(pinned) != 0 {
		t.Errorf("pinned should be empty for nil input, got %d", len(pinned))
	}
	if len(remaining) != 0 {
		t.Errorf("remaining should be empty for nil input, got %d", len(remaining))
	}
}
