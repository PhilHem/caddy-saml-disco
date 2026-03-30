//go:build unit

package domain

import (
	"testing"
)

func TestEntitlement_Validate(t *testing.T) {
	tests := []struct {
		name    string
		e       Entitlement
		wantErr bool
	}{
		{"valid exact", Entitlement{Subject: "user@example.edu"}, false},
		{"valid pattern", Entitlement{Pattern: "*@example.edu"}, false},
		{"both subject and pattern", Entitlement{Subject: "x", Pattern: "y"}, true},
		{"neither subject nor pattern", Entitlement{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.e.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Entitlement.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatchesSubjectPattern(t *testing.T) {
	tests := []struct {
		subject, pattern string
		want             bool
	}{
		{"user@example.edu", "*@example.edu", true},
		{"staff@mit.edu", "staff@*", true},
		{"admin@example.edu", "admin@example.edu", true},
		{"other@foo.com", "*@example.edu", false},
		{"user@example.edu", "*", true},
		{"user@example.edu", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.subject+"_"+tt.pattern, func(t *testing.T) {
			got := MatchesSubjectPattern(tt.subject, tt.pattern)
			if got != tt.want {
				t.Errorf("MatchesSubjectPattern(%q, %q) = %v, want %v", tt.subject, tt.pattern, got, tt.want)
			}
		})
	}
}
