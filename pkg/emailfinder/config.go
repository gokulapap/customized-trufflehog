package emailfinder

import (
	"bufio"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/gobwas/glob"
)

//go:embed blocklists/usernames.txt
var defaultInterestingUsernames []byte

//go:embed blocklists/trash_usernames.txt
var defaultTrashUsernames []byte

//go:embed blocklists/domains.txt
var defaultDomains []byte

//go:embed blocklists/paths.txt
var defaultPaths []byte

// Config holds filter configuration. Lists are replaceable / appendable via Options.
type Config struct {
	// InterestingUsernames are role/contact locals the user wants kept
	// (support, devops, …). Maintained in usernames.txt. Personal emails
	// like john.doe@ are kept without being on this list.
	InterestingUsernames map[string]struct{}
	// TrashUsernames are junk locals always dropped (noreply, test, foo, …).
	TrashUsernames map[string]struct{}
	BlockedDomains map[string]struct{}
	ExcludePaths   []glob.Glob
	rawPathPatterns []string
}

// Options configures how Config is loaded.
type Options struct {
	// Replace embedded interesting usernames (usernames.txt).
	UsernamesFile string
	// Replace embedded trash usernames.
	TrashUsernamesFile string
	// Replace embedded domain blocklist.
	DomainsFile string
	// Replace embedded path exclude patterns.
	PathsFile string

	// Appended on top of (possibly replaced) defaults.
	ExtraUsernamesFile      string
	ExtraTrashUsernamesFile string
	ExtraDomainsFile        string
	ExtraPathsFile          string
}

// DefaultConfig loads embedded lists.
func DefaultConfig() (*Config, error) {
	return LoadConfig(Options{})
}

// LoadConfig builds a Config from embedded defaults and optional override/extra files.
func LoadConfig(opts Options) (*Config, error) {
	cfg := &Config{
		InterestingUsernames: make(map[string]struct{}),
		TrashUsernames:       make(map[string]struct{}),
		BlockedDomains:       make(map[string]struct{}),
	}

	interesting := defaultInterestingUsernames
	if opts.UsernamesFile != "" {
		b, err := os.ReadFile(opts.UsernamesFile)
		if err != nil {
			return nil, fmt.Errorf("email usernames file: %w", err)
		}
		interesting = b
	}
	mergeLines(interesting, cfg.InterestingUsernames)
	if opts.ExtraUsernamesFile != "" {
		b, err := os.ReadFile(opts.ExtraUsernamesFile)
		if err != nil {
			return nil, fmt.Errorf("email extra usernames file: %w", err)
		}
		mergeLines(b, cfg.InterestingUsernames)
	}

	trash := defaultTrashUsernames
	if opts.TrashUsernamesFile != "" {
		b, err := os.ReadFile(opts.TrashUsernamesFile)
		if err != nil {
			return nil, fmt.Errorf("email trash usernames file: %w", err)
		}
		trash = b
	}
	mergeLines(trash, cfg.TrashUsernames)
	if opts.ExtraTrashUsernamesFile != "" {
		b, err := os.ReadFile(opts.ExtraTrashUsernamesFile)
		if err != nil {
			return nil, fmt.Errorf("email extra trash usernames file: %w", err)
		}
		mergeLines(b, cfg.TrashUsernames)
	}

	domains := defaultDomains
	if opts.DomainsFile != "" {
		b, err := os.ReadFile(opts.DomainsFile)
		if err != nil {
			return nil, fmt.Errorf("email domains file: %w", err)
		}
		domains = b
	}
	mergeLines(domains, cfg.BlockedDomains)
	if opts.ExtraDomainsFile != "" {
		b, err := os.ReadFile(opts.ExtraDomainsFile)
		if err != nil {
			return nil, fmt.Errorf("email extra domains file: %w", err)
		}
		mergeLines(b, cfg.BlockedDomains)
	}

	paths := defaultPaths
	if opts.PathsFile != "" {
		b, err := os.ReadFile(opts.PathsFile)
		if err != nil {
			return nil, fmt.Errorf("email paths file: %w", err)
		}
		paths = b
	}
	pathPatterns := parseLines(paths)
	if opts.ExtraPathsFile != "" {
		b, err := os.ReadFile(opts.ExtraPathsFile)
		if err != nil {
			return nil, fmt.Errorf("email extra paths file: %w", err)
		}
		pathPatterns = append(pathPatterns, parseLines(b)...)
	}
	if err := cfg.setPathPatterns(pathPatterns); err != nil {
		return nil, err
	}

	return cfg, nil
}

func mergeLines(data []byte, dest map[string]struct{}) {
	for _, line := range parseLines(data) {
		dest[strings.ToLower(line)] = struct{}{}
	}
}

func (c *Config) setPathPatterns(patterns []string) error {
	c.rawPathPatterns = patterns
	c.ExcludePaths = c.ExcludePaths[:0]
	for _, p := range patterns {
		g, err := glob.Compile(filepath.ToSlash(p), '/')
		if err != nil {
			return fmt.Errorf("invalid email path pattern %q: %w", p, err)
		}
		c.ExcludePaths = append(c.ExcludePaths, g)
	}
	return nil
}

func parseLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// ShouldSkipPath reports whether emails from filePath should be ignored.
func (c *Config) ShouldSkipPath(filePath string) bool {
	if c == nil || filePath == "" || len(c.ExcludePaths) == 0 {
		return false
	}
	normalized := filepath.ToSlash(filePath)
	for _, g := range c.ExcludePaths {
		if g.Match(normalized) {
			return true
		}
	}
	return false
}

// IsBlockedEmail reports whether localPart@domain should be filtered out.
// Interesting role usernames (usernames.txt) are never dropped for local-part
// reasons. Personal emails are kept unless domain/path/trash filters apply.
func (c *Config) IsBlockedEmail(localPart, domain string) (bool, string) {
	if c == nil {
		return false, ""
	}
	local := strings.ToLower(strings.TrimSpace(localPart))
	dom := strings.ToLower(strings.TrimSpace(domain))

	if local == "" || dom == "" {
		return true, "empty"
	}

	if _, ok := c.BlockedDomains[dom]; ok {
		return true, "blocked domain"
	}
	for blocked := range c.BlockedDomains {
		if strings.HasSuffix(dom, "."+blocked) {
			return true, "blocked domain suffix"
		}
	}

	// Role/contact locals from usernames.txt always stay (domain already OK).
	if _, interesting := c.InterestingUsernames[local]; interesting {
		return false, ""
	}

	if _, ok := c.TrashUsernames[local]; ok {
		return true, "trash username"
	}
	if strings.Contains(local, "noreply") || strings.Contains(local, "no-reply") ||
		strings.Contains(local, "donotreply") || strings.Contains(local, "do-not-reply") {
		return true, "noreply local-part"
	}
	return false, ""
}

// Collector accumulates unique emails across a scan (thread-safe).
type Collector struct {
	mu     sync.Mutex
	emails map[string]struct{}
}

func NewCollector() *Collector {
	return &Collector{emails: make(map[string]struct{})}
}

func (c *Collector) Add(email string) {
	if c == nil {
		return
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return
	}
	c.mu.Lock()
	c.emails[email] = struct{}{}
	c.mu.Unlock()
}

func (c *Collector) Count() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.emails)
}

// UniqueSorted returns unique emails sorted alphabetically.
func (c *Collector) UniqueSorted() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.emails))
	for e := range c.emails {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// CommaSeparated returns unique emails as a single CSV string.
func (c *Collector) CommaSeparated() string {
	return strings.Join(c.UniqueSorted(), ",")
}
