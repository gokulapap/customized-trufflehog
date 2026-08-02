package emailfinder

import (
	"regexp"
	"strings"
	"unicode"
)

var (
	// Strict local-part: start/end alnum, middle may include ._%+-
	strictLocalRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._%+-]{0,62}[a-z0-9]$|^[a-z0-9]$`)
	// Domain labels + TLD (letters only, len>=2)
	strictDomainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*\.[a-z]{2,24}$`)
)

// Mode controls how aggressively emails are kept.
type Mode string

const (
	// ModeFiltered collects candidates (trash/paths/domains stripped), then keeps
	// only domains that have >=2 distinct emails.
	ModeFiltered Mode = "filtered"
	// ModeRoles keeps only local-parts listed in usernames.txt.
	ModeRoles Mode = "roles"
	// ModeAll keeps anything that passes trash/domain/path/structure checks
	// (no domain-count gate).
	ModeAll Mode = "all"
	// ModeUnfiltered keeps well-formed emails except blocked spam domains.
	// Skips path/trash/noise/count filters — for offline analysis.
	ModeUnfiltered Mode = "unfiltered"
)

func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModeRoles):
		return ModeRoles
	case string(ModeAll):
		return ModeAll
	case string(ModeUnfiltered):
		return ModeUnfiltered
	default:
		return ModeFiltered
	}
}

// IsNoiseLocal drops test/staging-style local-parts beyond the explicit trash list.
func IsNoiseLocal(local string) bool {
	local = strings.ToLower(strings.TrimSpace(local))
	if local == "" {
		return false
	}
	// Strip +tag for matching (engineering+1 stays; test+foo drops).
	if i := strings.IndexByte(local, '+'); i > 0 {
		local = local[:i]
	}
	if local == "staging" || strings.HasPrefix(local, "staging") ||
		local == "uat" || local == "qa" || local == "sandbox" {
		return true
	}
	if strings.HasPrefix(local, "test") {
		return true
	}
	// transmstest, loadtest, etc.
	if len(local) > 4 && strings.HasSuffix(local, "test") {
		return true
	}
	return false
}

// IsNoiseDomain drops GCP service accounts and test/staging hostnames.
func IsNoiseDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	if domain == "gserviceaccount.com" || strings.HasSuffix(domain, ".gserviceaccount.com") {
		return true
	}
	parts := strings.Split(domain, ".")
	for _, p := range parts[:len(parts)-1] { // skip public TLD-ish last label
		switch p {
		case "test", "testing", "staging", "uat", "qa", "sandbox", "localhost":
			return true
		}
	}
	// testdozr.com, test-env.example.com
	if len(parts) >= 2 && strings.HasPrefix(parts[0], "test") {
		return true
	}
	return false
}

// IsWellFormed rejects binary garbage and protocol-ish false positives.
func IsWellFormed(local, domain string) bool {
	local = strings.ToLower(strings.TrimSpace(local))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if local == "" || domain == "" {
		return false
	}
	if len(local) > 64 || len(domain) > 253 {
		return false
	}
	if strings.Contains(local, "..") || strings.Contains(domain, "..") {
		return false
	}
	if !strictLocalRe.MatchString(local) {
		return false
	}
	if !strictDomainRe.MatchString(domain) {
		return false
	}
	// Reject locals that are mostly digits/symbols noise.
	letters := 0
	for _, r := range local {
		if unicode.IsLetter(r) {
			letters++
		}
	}
	if letters == 0 {
		return false
	}
	// OpenSSH cipher/kex style: "aes128-gcm", "hmac-sha2-256-etm", "curve25519-sha256"
	if looksLikeCryptoIdentifier(local) {
		return false
	}
	// Reject GitHub Actions-ish action refs mistaken as emails: docker/scout-action@v1.11.0
	if strings.Contains(domain, "/") || strings.HasPrefix(domain, "v") && strings.ContainsAny(domain, "0123456789") {
		// domain validation already blocks '/', but keep for safety
		return false
	}
	if strings.HasPrefix(local, "cilk_") || strings.HasPrefix(local, "cilklib") {
		return false
	}
	return true
}

func looksLikeCryptoIdentifier(local string) bool {
	cryptoHints := []string{
		"aes", "hmac", "sha1", "sha2", "sha256", "sha512", "chacha", "poly1305",
		"curve25519", "ecdsa", "ed25519", "rsa-", "dss-", "umac-", "rijndael",
		"gcm@", // shouldn't appear in local
		"-etm", "-cert-", "streamlocal", "hostkeys", "auth-agent",
	}
	for _, h := range cryptoHints {
		if strings.Contains(local, h) {
			return true
		}
	}
	hyphens := strings.Count(local, "-")
	if hyphens >= 2 && strings.ContainsAny(local, "0123456789") {
		return true
	}
	return false
}
