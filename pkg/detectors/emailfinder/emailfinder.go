package emailfinder

import (
	"context"

	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors/filedump"
	ef "github.com/trufflesecurity/trufflehog/v3/pkg/emailfinder"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

// Scanner finds emails and records them in a shared Collector.
// It intentionally returns no Result findings so output stays a single
// end-of-scan comma-separated list.
type Scanner struct {
	Config    *ef.Config
	Collector *ef.Collector
}

var _ detectors.Detector = (*Scanner)(nil)

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_EmailFinder
}

func (s Scanner) Description() string {
	return "Finds unique email addresses while filtering common usernames, vendor domains, and package paths."
}

func (s Scanner) Keywords() []string {
	return []string{"@"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	_ = verify
	if s.Config == nil || s.Collector == nil {
		return nil, nil
	}
	filePath, _ := ctx.Value(filedump.FilePathContextKey{}).(string)
	for _, email := range ef.Extract(data, filePath, s.Config) {
		s.Collector.Add(email, filePath)
	}
	// No per-match results: emails are printed once as a CSV summary after the scan.
	return nil, nil
}
