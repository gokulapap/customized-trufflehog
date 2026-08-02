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
	// ModeFiltered keeps role usernames + clean personal emails on non-blocked domains.
	ModeFiltered Mode = "filtered"
	// ModeRoles keeps only local-parts listed in usernames.txt.
	ModeRoles Mode = "roles"
	// ModeAll keeps anything that passes trash/domain/path/structure checks.
	ModeAll Mode = "all"
)

func ParseMode(s string) Mode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(ModeRoles):
		return ModeRoles
	case string(ModeAll):
		return ModeAll
	default:
		return ModeFiltered
	}
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
