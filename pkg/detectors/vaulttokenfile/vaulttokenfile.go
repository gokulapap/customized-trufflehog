package vaulttokenfile

import (
	"context"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/filedump"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct{}

var _ interface {
	detectors.Detector
	detectors.FilenameMatcher
	detectors.MaxSecretSizeProvider
	detectors.CustomFalsePositiveChecker
} = (*Scanner)(nil)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_VaultTokenFile
}

func (s Scanner) Description() string {
	return "HashiCorp Vault token files (.vault-token) that grant direct Vault API access."
}

// Keywords is intentionally empty: this detector is filename-triggered only.
func (s Scanner) Keywords() []string {
	return nil
}

func (s Scanner) FilenamePatterns() []string {
	return []string{".vault-token", ".vault-token.json", "vault-token", "vault-root-token.txt"}
}

func (s Scanner) MaxSecretSize() int64 {
	return filedump.MaxDumpBytes
}

func (s Scanner) IsFalsePositive(result detectors.Result) (bool, string) {
	return filedump.IsFalsePositive(result)
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	if filedump.ShouldSkip(data) {
		return nil, nil
	}
	_ = verify
	filePath, _ := ctx.Value(filedump.FilePathContextKey{}).(string)
	results = append(results, filedump.Result(s.Type(), filePath, data))
	return results, nil
}
