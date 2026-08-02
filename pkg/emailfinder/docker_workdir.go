package emailfinder

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// DetectDockerWorkingDir returns the image Config.WorkingDir via `docker inspect`
// for local daemon images (docker://… or bare refs). Empty if unknown / unavailable.
func DetectDockerWorkingDir(imageRef string) (string, error) {
	ref := strings.TrimSpace(imageRef)
	ref = strings.TrimPrefix(ref, "docker://")
	if ref == "" || strings.HasPrefix(ref, "file://") {
		return "", nil
	}
	// Registry-only refs without a local daemon copy may fail; caller treats as optional.
	cmd := exec.Command("docker", "inspect", "--format", "{{.Config.WorkingDir}}", ref)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker inspect %s: %w (%s)", ref, err, strings.TrimSpace(stderr.String()))
	}
	wd := strings.TrimSpace(stdout.String())
	if wd == "" || wd == "<no value>" {
		return "", nil
	}
	return NormalizeAppRoot(wd), nil
}
