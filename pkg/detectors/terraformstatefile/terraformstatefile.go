package terraformstatefile

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
	return detectorspb.DetectorType_TerraformStateFile
}

func (s Scanner) Description() string {
	return "Terraform state files that frequently embed provider credentials and resource secrets in JSON."
}

// Keywords is intentionally empty: this detector is filename-triggered only.
func (s Scanner) Keywords() []string {
	return nil
}

func (s Scanner) FilenamePatterns() []string {
	return []string{"terraform.tfstate", "terraform.tfstate.backup", "*.tfstate", "*.tfstate.backup"}
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
