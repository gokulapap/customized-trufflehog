package emailfinder_test

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/emailfinder"
)

func TestExtractKeepsRoleAndPersonal(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte(`
devops@acme-corp.io
support@acme-corp.io
security@example.com
author@users.noreply.github.com
real.person@acme-corp.io
john.doe@partner.io
noreply@acme-corp.io
test@acme-corp.io
`)
	got := emailfinder.Extract(data, "/app/config.yaml", cfg)
	want := map[string]bool{
		"devops@acme-corp.io":      true,
		"support@acme-corp.io":     true,
		"real.person@acme-corp.io": true,
		"john.doe@partner.io":      true,
	}
	if len(got) != len(want) {
		t.Fatalf("want %d emails, got %d: %v", len(want), len(got), got)
	}
	for _, e := range got {
		if !want[e] {
			t.Fatalf("unexpected kept email: %s (all=%v)", e, got)
		}
	}
}

func TestSkipVendorPath(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`real.person@acme-corp.io`)
	got := emailfinder.Extract(data, "/app/node_modules/pkg/index.js", cfg)
	if len(got) != 0 {
		t.Fatalf("expected skip for node_modules, got %v", got)
	}
}

func TestCollectorCSV(t *testing.T) {
	c := emailfinder.NewCollector()
	c.Add("b@x.com")
	c.Add("a@x.com")
	c.Add("b@x.com")
	if c.CommaSeparated() != "a@x.com,b@x.com" {
		t.Fatalf("got %q", c.CommaSeparated())
	}
}
