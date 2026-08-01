package filedump

import (
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

const (
	// MaxDumpBytes caps how much of a matched file is emitted as a finding.
	MaxDumpBytes = 800 * 1024
)

// FilePathContextKey is used by the engine to pass the source file path into
// filename-triggered detectors via context.Context.
type FilePathContextKey struct{}

// MatchFilename reports whether filePath matches any of the given patterns.
// Patterns may be basename globs (".env.*") or path suffixes (".kube/config").
func MatchFilename(filePath string, patterns []string) bool {
	if filePath == "" || len(patterns) == 0 {
		return false
	}
	normalized := filepath.ToSlash(filePath)
	base := filepath.Base(normalized)

	for _, pattern := range patterns {
		pattern = filepath.ToSlash(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}

		// Exact basename match.
		if pattern == base {
			return true
		}

		// Path suffix match for nested paths like ".kube/config" or ".aws/credentials".
		if strings.Contains(pattern, "/") {
			if strings.HasSuffix(normalized, pattern) || strings.HasSuffix(normalized, "/"+pattern) {
				return true
			}
			if g, err := glob.Compile(pattern); err == nil && g.Match(normalized) {
				return true
			}
			continue
		}

		// Basename glob (supports *, ?).
		if g, err := glob.Compile(pattern); err == nil && g.Match(base) {
			return true
		}
		if ok, err := filepath.Match(pattern, base); err == nil && ok {
			return true
		}
	}
	return false
}

// Result builds a verified whole-file dump finding.
// Verified is set without network checks so --only-verified keeps these hits:
// matching a known sensitive filename is treated as sufficient confirmation.
func Result(detectorType detectorspb.DetectorType, filePath string, data []byte) detectors.Result {
	payload := data
	truncated := false
	if len(payload) > MaxDumpBytes {
		payload = payload[:MaxDumpBytes]
		truncated = true
	}

	redacted := filepath.Base(filepath.ToSlash(filePath))
	if redacted == "" || redacted == "." {
		redacted = detectorType.String()
	}

	extra := map[string]string{
		"file": redacted,
	}
	if filePath != "" {
		extra["path"] = filepath.ToSlash(filePath)
	}
	if truncated {
		extra["truncated"] = "true"
	}

	return detectors.Result{
		DetectorType: detectorType,
		DetectorName: detectorType.String(),
		Verified:     true,
		// Short label for "Raw result:"; full dump goes in RawV2 as "Raw result (full):".
		Raw:       []byte(redacted),
		RawV2:     payload,
		Redacted:  redacted,
		ExtraData: extra,
	}
}

// ShouldSkip returns true when the chunk is empty or looks binary.
func ShouldSkip(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	// Skip obvious binary payloads.
	for _, b := range data[:min(len(data), 1024)] {
		if b == 0 {
			return true
		}
	}
	return false
}

// IsFalsePositive always returns false. Whole-file dumps intentionally contain
// ordinary words (password, example, sample, etc.) that would otherwise be
// stripped by the default false-positive wordlist.
func IsFalsePositive(_ detectors.Result) (bool, string) {
	return false, ""
}
