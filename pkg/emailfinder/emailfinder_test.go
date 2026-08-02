package emailfinder_test

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/emailfinder"
)

func TestDefaultKeepsOnlyRolesOnCleanPaths(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte(`
devops@dozr.com
support@dozr.com
adeel@dozr.com
admin@stephenbelanger.com
anna@addaleax.net
someone@gmail.com
aes128-gcm@openssh.com
`)
	gotApp := emailfinder.Extract(data, "/app/config/settings.env", cfg)
	want := map[string]bool{
		"devops@dozr.com":             true,
		"support@dozr.com":            true,
		"admin@stephenbelanger.com":   true, // admin is a role username; domain not freemail-blocked here
	}
	// gmail blocked, personal adeel dropped (not in usernames), openssh malformed/crypto
	for _, e := range gotApp {
		if e == "adeel@dozr.com" || e == "someone@gmail.com" {
			t.Fatalf("should not keep %s: %v", e, gotApp)
		}
	}
	if !contains(gotApp, "devops@dozr.com") || !contains(gotApp, "support@dozr.com") {
		t.Fatalf("want role@dozr kept, got %v", gotApp)
	}
	_ = want

	gotJunk := emailfinder.Extract(data, "/usr/share/doc/openssh/README", cfg)
	if len(gotJunk) != 0 {
		t.Fatalf("junk path should drop all, got %v", gotJunk)
	}

	gotNPM := emailfinder.Extract([]byte(`admin@stephenbelanger.com`), "/app/node_modules/foo/package.json", cfg)
	if len(gotNPM) != 0 {
		t.Fatalf("node_modules should drop role hits, got %v", gotNPM)
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
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
