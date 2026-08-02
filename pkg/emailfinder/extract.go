package emailfinder

import (
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var emailRe = regexp.MustCompile(common.EmailPattern)

// Extract returns emails from data that pass pre-filters for the active mode.
// For ModeFiltered, this returns candidate emails; Final selection is done by
// Collector.Finalize (domain grouping).
func Extract(data []byte, filePath string, cfg *Config) []string {
	if len(data) == 0 || cfg == nil {
		return nil
	}
	if cfg.Mode != ModeUnfiltered && cfg.ShouldSkipPath(filePath) {
		return nil
	}

	matches := emailRe.FindAllStringSubmatch(string(data), -1)
	if len(matches) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(matches))
	var out []string
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		email := strings.ToLower(strings.TrimSpace(m[1]))
		email = strings.Trim(email, `"' <>`)
		if email == "" {
			continue
		}
		at := strings.LastIndex(email, "@")
		if at <= 0 || at == len(email)-1 {
			continue
		}
		local, domain := email[:at], email[at+1:]
		if !cfg.IsCandidate(local, domain, filePath) {
			continue
		}
		// Roles mode: only whitelist locals.
		if cfg.Mode == ModeRoles {
			if _, ok := cfg.InterestingUsernames[local]; !ok {
				continue
			}
		}
		if _, ok := seen[email]; ok {
			continue
		}
		seen[email] = struct{}{}
		out = append(out, email)
	}
	return out
}

// SplitEmail returns local-part and domain (lowercased).
func SplitEmail(email string) (local, domain string, ok bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return "", "", false
	}
	return email[:at], email[at+1:], true
}
