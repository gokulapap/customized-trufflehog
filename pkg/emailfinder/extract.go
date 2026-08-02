package emailfinder

import (
	"regexp"
	"strings"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
)

var emailRe = regexp.MustCompile(common.EmailPattern)

// Extract returns unique emails from data that pass Config filters.
// filePath is optional and used for path-based exclusion.
func Extract(data []byte, filePath string, cfg *Config) []string {
	if len(data) == 0 || cfg == nil {
		return nil
	}
	if cfg.ShouldSkipPath(filePath) {
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
		if keep, _ := cfg.ShouldKeepEmail(local, domain, filePath); !keep {
			continue
		}
		if _, ok := seen[email]; ok {
			continue
		}
		seen[email] = struct{}{}
		out = append(out, email)
	}
	return out
}
