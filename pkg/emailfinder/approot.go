package emailfinder

import (
	"path/filepath"
	"strings"
)

// nestedJunkPatterns still apply under AppRoots (WORKDIR).
// Keep this list dependency-/artifact-focused only.
// Do NOT include **/lib/**, **/dist/**, **/build/** — those are often the
// shipped application in containers (/app/lib, /app/dist).
var nestedJunkPatterns = []string{
	"**/node_modules/**",
	"**/vendor/**",
	"**/.git/**",
	"**/site-packages/**",
	"**/dist-packages/**",
	"**/.venv/**",
	"**/venv/**",
	"**/__pycache__/**",
	"**/.tox/**",
	"**/.pnpm/**",
	"**/.yarn/**",
	"**/bower_components/**",
	"**/jspm_packages/**",
	"**/.bundle/**",
	"**/vendor/bundle/**",
	"**/Pods/**",
	"**/Carthage/**",
	"**/.gradle/**",
	"**/.m2/**",
	"**/gems/**",
	"**/package-lock.json",
	"**/yarn.lock",
	"**/pnpm-lock.yaml",
	"**/composer.lock",
	"**/Pipfile.lock",
	"**/poetry.lock",
	"**/Cargo.lock",
	"**/go.sum",
	"**/Gemfile.lock",
	"**/*.min.js",
	"**/*.min.css",
	"**/*.map",
}

// ParseAppRoots splits a comma-separated --email-app-roots value.
func ParseAppRoots(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, NormalizeAppRoot(part))
	}
	return out
}

// NormalizeAppRoot slash-normalizes and trims trailing slashes (except root "/").
func NormalizeAppRoot(root string) string {
	root = filepath.ToSlash(strings.TrimSpace(root))
	if root == "" {
		return ""
	}
	if !strings.HasPrefix(root, "/") {
		root = "/" + root
	}
	if root != "/" {
		root = strings.TrimRight(root, "/")
	}
	return root
}

// IsUnderAppRoot reports whether filePath is inside any configured app root
// (Docker WORKDIR / manual --email-app-roots).
func (c *Config) IsUnderAppRoot(filePath string) bool {
	if c == nil || len(c.AppRoots) == 0 || filePath == "" {
		return false
	}
	norm := filepath.ToSlash(filePath)
	for _, root := range c.AppRoots {
		root = NormalizeAppRoot(root)
		if root == "" {
			continue
		}
		if root == "/" {
			return true
		}
		if norm == root || strings.HasPrefix(norm, root+"/") {
			return true
		}
	}
	return false
}

// SetAppRoots replaces configured app roots (WORKDIR / CLI overrides).
func (c *Config) SetAppRoots(roots []string) {
	if c == nil {
		return
	}
	c.AppRoots = c.AppRoots[:0]
	for _, r := range roots {
		r = NormalizeAppRoot(r)
		if r == "" {
			continue
		}
		c.AppRoots = append(c.AppRoots, r)
	}
}

// AddAppRoot appends a root if not already present.
func (c *Config) AddAppRoot(root string) {
	if c == nil {
		return
	}
	root = NormalizeAppRoot(root)
	if root == "" {
		return
	}
	for _, existing := range c.AppRoots {
		if existing == root {
			return
		}
	}
	c.AppRoots = append(c.AppRoots, root)
}
