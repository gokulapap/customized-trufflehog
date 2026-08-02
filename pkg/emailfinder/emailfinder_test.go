package emailfinder_test

import (
	"testing"

	"github.com/trufflesecurity/trufflehog/v3/pkg/emailfinder"
)

func TestExtractCandidatesSkipJunkAndBlocked(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte(`
devops@dozr.com
support@dozr.com
adeel@dozr.com
admin@partner-corp.io
anna@partner-corp.io
someone@gmail.com
aes128-gcm@openssh.com
hello@hiroppy.me
`)
	gotApp := emailfinder.Extract(data, "/app/config/settings.env", cfg)
	wantKeep := []string{
		"devops@dozr.com",
		"support@dozr.com",
		"adeel@dozr.com",
		"admin@partner-corp.io",
		"anna@partner-corp.io",
	}
	for _, e := range wantKeep {
		if !contains(gotApp, e) {
			t.Fatalf("want candidate %s in %v", e, gotApp)
		}
	}
	for _, e := range []string{"someone@gmail.com", "aes128-gcm@openssh.com", "hello@hiroppy.me"} {
		if contains(gotApp, e) {
			t.Fatalf("should not keep %s: %v", e, gotApp)
		}
	}

	gotJunk := emailfinder.Extract(data, "/usr/share/doc/openssh/README", cfg)
	if len(gotJunk) != 0 {
		t.Fatalf("junk path should drop all, got %v", gotJunk)
	}

	gotNPM := emailfinder.Extract([]byte(`admin@partner-corp.io`), "/app/node_modules/foo/package.json", cfg)
	if len(gotNPM) != 0 {
		t.Fatalf("node_modules should drop, got %v", gotNPM)
	}
}

func TestAppRootBoostsUsrSrcWorkdir(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetAppRoots([]string{"/usr/src/foreman"})

	got := emailfinder.Extract([]byte(`adeel@dozr.com`), "/usr/src/foreman/config/default.json", cfg)
	if !contains(got, "adeel@dozr.com") {
		t.Fatalf("WORKDIR under /usr/src should keep app emails, got %v", got)
	}

	gotNPM := emailfinder.Extract([]byte(`adeel@dozr.com`), "/usr/src/foreman/node_modules/x/package.json", cfg)
	if len(gotNPM) != 0 {
		t.Fatalf("node_modules under WORKDIR should still skip, got %v", gotNPM)
	}
}

func TestFinalizeDomainCountOnly(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetAppRoots([]string{"/usr/src/foreman"})
	c := emailfinder.NewCollector(cfg)

	c.Add("adeel@dozr.com", "/usr/src/foreman/app.js")
	c.Add("accounting@dozr.com", "/usr/src/foreman/config.js")
	c.Add("admin@partner-corp.io", "/tmp/notes.txt")  // lone role → drop
	c.Add("hello@mozilla.com", "/usr/src/foreman/pkg.json") // lone mozilla → drop
	c.Add("npm@somepackage.dev", "/opt/vendor/x.txt")       // different lone domain → drop
	c.Add("anna@other.io", "/tmp/notes.txt")                // lone personal → drop
	c.Add("a@foss.testcorp.io", "/opt/vendor/a.txt")
	c.Add("b@foss.testcorp.io", "/opt/vendor/b.txt")

	got := c.Finalize()
	want := []string{
		"a@foss.testcorp.io",
		"accounting@dozr.com",
		"adeel@dozr.com",
		"b@foss.testcorp.io",
	}
	for _, e := range []string{"admin@partner-corp.io", "hello@mozilla.com", "npm@somepackage.dev", "anna@other.io"} {
		if contains(got, e) {
			t.Fatalf("count<2 should drop %s: %v", e, got)
		}
	}
	for _, e := range want {
		if !contains(got, e) {
			t.Fatalf("want %s kept, got %v", e, got)
		}
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
	c := emailfinder.NewCollector(nil)
	c.Add("b@x.com", "/app/a")
	c.Add("a@x.com", "/app/b")
	c.Add("b@x.com", "/app/c")
	if c.CommaSeparated() != "a@x.com,b@x.com" {
		t.Fatalf("got %q", c.CommaSeparated())
	}
}

func TestDropsTestAndGCPNoise(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetAppRoots([]string{"/usr/src/foreman"})
	data := []byte(`
adeel@dozr.com
staging@dozr.com
testdozr@testdozr.com
testforeman@test.dozr.com
testuser2@testdozr.com
transmstest@test.dozr.com
devops@dozr-1053.iam.gserviceaccount.com
pubsub-account@dozr-1053.iam.gserviceaccount.com
notifications@dozr.com
`)
	got := emailfinder.Extract(data, "/usr/src/foreman/app.js", cfg)
	if !contains(got, "adeel@dozr.com") || !contains(got, "notifications@dozr.com") {
		t.Fatalf("want real contacts kept, got %v", got)
	}
	for _, e := range []string{
		"staging@dozr.com",
		"testdozr@testdozr.com",
		"testforeman@test.dozr.com",
		"testuser2@testdozr.com",
		"transmstest@test.dozr.com",
		"devops@dozr-1053.iam.gserviceaccount.com",
		"pubsub-account@dozr-1053.iam.gserviceaccount.com",
	} {
		if contains(got, e) {
			t.Fatalf("should drop noise %s, got %v", e, got)
		}
	}
}

func TestUnfilteredSpamDomainsOnly(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Mode = emailfinder.ModeUnfiltered

	data := []byte(`
adeel@dozr.com
hello@mozilla.com
someone@gmail.com
noreply@dozr.com
admin@partner-corp.io
`)
	// node_modules path is scanned in unfiltered mode
	got := emailfinder.Extract(data, "/app/node_modules/foo/package.json", cfg)
	if !contains(got, "adeel@dozr.com") || !contains(got, "hello@mozilla.com") || !contains(got, "noreply@dozr.com") || !contains(got, "admin@partner-corp.io") {
		t.Fatalf("unfiltered should keep non-spam emails from any path, got %v", got)
	}
	if contains(got, "someone@gmail.com") {
		t.Fatalf("unfiltered should still drop blocked spam domains, got %v", got)
	}

	c := emailfinder.NewCollector(cfg)
	for _, e := range got {
		c.Add(e, "/app/node_modules/foo/package.json")
	}
	c.Add("lonely@example-org.io", "/x")
	final := c.Finalize()
	// no domain-count gate
	if !contains(final, "lonely@example-org.io") || !contains(final, "hello@mozilla.com") {
		t.Fatalf("unfiltered finalize should keep count==1 emails, got %v", final)
	}
}

func TestAnchoredOSPathsDoNotKillAppLib(t *testing.T) {
	cfg, err := emailfinder.DefaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	// No AppRoot: full paths.txt applies, but /app/lib must survive.
	if cfg.ShouldSkipPath("/app/lib/utils.js") {
		t.Fatal("/app/lib should not be skipped by anchored /lib/**")
	}
	if cfg.ShouldSkipPath("/app/src/main.py") {
		t.Fatal("/app/src should not be skipped")
	}
	if cfg.ShouldSkipPath("/app/dist/bundle.js") {
		t.Fatal("/app/dist should not be skipped by default list anymore")
	}
	if !cfg.ShouldSkipPath("/usr/lib/libssl.so") {
		t.Fatal("/usr/lib should be skipped")
	}
	if !cfg.ShouldSkipPath("/lib/x86_64-linux-gnu/libc.so") {
		t.Fatal("/lib should be skipped")
	}
	if !cfg.ShouldSkipPath("/app/node_modules/foo/index.js") {
		t.Fatal("node_modules should still be skipped")
	}
}
