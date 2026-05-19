package redact_test

import (
	"regexp"
	"testing"

	"github.com/karthikeyan5/sshgate/src/redact"
)

func TestSortRulesDeduplicatesByID(t *testing.T) {
	dup := []redact.Rule{
		{ID: "b", Regex: regexp.MustCompile(`b`)},
		{ID: "a", Regex: regexp.MustCompile(`a1`)},
		{ID: "a", Regex: regexp.MustCompile(`a2`)},
	}
	out := redact.SortRules(dup)
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if out[0].ID != "a" || out[1].ID != "b" {
		t.Errorf("order = %s,%s want a,b", out[0].ID, out[1].ID)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		rules   []redact.Rule
		wantErr bool
	}{
		{
			name:    "empty is ok",
			rules:   nil,
			wantErr: false,
		},
		{
			name: "valid rule",
			rules: []redact.Rule{
				{ID: "x", Regex: regexp.MustCompile(`(foo)`), SecretGroup: 1},
			},
			wantErr: false,
		},
		{
			name: "empty ID",
			rules: []redact.Rule{
				{ID: "", Regex: regexp.MustCompile(`foo`)},
			},
			wantErr: true,
		},
		{
			name: "nil regex",
			rules: []redact.Rule{
				{ID: "x", Regex: nil},
			},
			wantErr: true,
		},
		{
			name: "out-of-range secret group",
			rules: []redact.Rule{
				{ID: "x", Regex: regexp.MustCompile(`foo`), SecretGroup: 3},
			},
			wantErr: true,
		},
		{
			name: "duplicate ID",
			rules: []redact.Rule{
				{ID: "x", Regex: regexp.MustCompile(`a`)},
				{ID: "x", Regex: regexp.MustCompile(`b`)},
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := redact.Validate(tc.rules)
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestCompileRulePanicsOnBadRegex(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("expected panic for bad regex")
		}
	}()
	_ = redact.CompileRule("bad", "bad", "([", nil, 0, 0, 0)
}
