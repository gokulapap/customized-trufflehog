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
	Mode Mode
	// MinDomainEmailCount is used by ModeFiltered (outside AppRoots): keep a
	// domain's emails when it has at least this many distinct addresses.
	MinDomainEmailCount int
	// AppRoots are trusted app prefixes (Docker WORKDIR, --email-app-roots).
	// Candidates under these roots get a boost in ModeFiltered.
	AppRoots []string
	// InterestingUsernames are role/contact locals (support, devops, …).
	InterestingUsernames map[string]struct{}
	// TrashUsernames are junk locals always dropped (noreply, test, foo, …).
	TrashUsernames  map[string]struct{}
	BlockedDomains  map[string]struct{}
	ExcludePaths    []glob.Glob
	nestedJunk      []glob.Glob
	rawPathPatterns []string
}

// Options configures how Config is loaded.
type Options struct {
	Mode Mode

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

	// AppRoots are trusted app prefixes (e.g. Docker WORKDIR).
	AppRoots []string
}

// DefaultConfig loads embedded lists.
func DefaultConfig() (*Config, error) {
	return LoadConfig(Options{})
}

// LoadConfig builds a Config from embedded defaults and optional override/extra files.
func LoadConfig(opts Options) (*Config, error) {
	cfg := &Config{
		Mode:                 ModeFiltered,
		MinDomainEmailCount:  2,
		InterestingUsernames: make(map[string]struct{}),
		TrashUsernames:       make(map[string]struct{}),
		BlockedDomains:       make(map[string]struct{}),
	}
	if opts.Mode != "" {
		cfg.Mode = opts.Mode
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
	if err := cfg.setNestedJunkPatterns(nestedJunkPatterns); err != nil {
		return nil, err
	}
	if len(opts.AppRoots) > 0 {
		cfg.SetAppRoots(opts.AppRoots)
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

func (c *Config) setNestedJunkPatterns(patterns []string) error {
	c.nestedJunk = c.nestedJunk[:0]
	for _, p := range patterns {
		g, err := glob.Compile(filepath.ToSlash(p), '/')
		if err != nil {
			return fmt.Errorf("invalid nested junk path pattern %q: %w", p, err)
		}
		c.nestedJunk = append(c.nestedJunk, g)
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

// ShouldSkipPath reports whether emails from filePath should be ignored as junk/vendor paths.
// Unknown/empty paths are treated as untrusted (skipped) so role hits require a real app path.
// Under AppRoots (WORKDIR), only nested vendor junk is skipped — OS globs like **/usr/src/**
// do not suppress the application tree itself.
func (c *Config) ShouldSkipPath(filePath string) bool {
	if filePath == "" {
		return true
	}
	if c == nil {
		return false
	}
	normalized := filepath.ToSlash(filePath)
	patterns := c.ExcludePaths
	if c.IsUnderAppRoot(normalized) {
		patterns = c.nestedJunk
	}
	if len(patterns) == 0 {
		return false
	}
	for _, g := range patterns {
		if g.Match(normalized) {
			return true
		}
	}
	return false
}

// IsCandidate reports whether an address passes mode-specific pre-filters.
func (c *Config) IsCandidate(localPart, domain, filePath string) bool {
	if c == nil {
		return false
	}
	local := strings.ToLower(strings.TrimSpace(localPart))
	dom := strings.ToLower(strings.TrimSpace(domain))
	if local == "" || dom == "" {
		return false
	}
	if !IsWellFormed(local, dom) {
		return false
	}
	if c.IsBlockedDomain(dom) {
		return false
	}
	// Analysis mode: spam domains + structure only.
	if c.Mode == ModeUnfiltered {
		return true
	}
	if c.ShouldSkipPath(filePath) {
		return false
	}
	if _, ok := c.TrashUsernames[local]; ok {
		return false
	}
	if strings.Contains(local, "noreply") || strings.Contains(local, "no-reply") ||
		strings.Contains(local, "donotreply") || strings.Contains(local, "do-not-reply") {
		return false
	}
	if IsNoiseLocal(local) || IsNoiseDomain(dom) {
		return false
	}
	return true
}

// IsBlockedDomain reports whether domain is on the spam/vendor blocklist
// (exact or subdomain suffix match).
func (c *Config) IsBlockedDomain(domain string) bool {
	if c == nil {
		return false
	}
	dom := strings.ToLower(strings.TrimSpace(domain))
	if dom == "" {
		return false
	}
	if _, ok := c.BlockedDomains[dom]; ok {
		return true
	}
	for blocked := range c.BlockedDomains {
		if strings.HasSuffix(dom, "."+blocked) {
			return true
		}
	}
	return false
}

// ShouldKeepEmail is used by ModeRoles / ModeAll for immediate keep decisions.
// ModeFiltered uses IsCandidate + Collector.Finalize instead.
func (c *Config) ShouldKeepEmail(localPart, domain, filePath string) (bool, string) {
	if !c.IsCandidate(localPart, domain, filePath) {
		return false, "not a candidate"
	}
	local := strings.ToLower(strings.TrimSpace(localPart))
	switch c.Mode {
	case ModeAll, ModeUnfiltered:
		return true, string(c.Mode)
	case ModeRoles:
		if _, ok := c.InterestingUsernames[local]; ok {
			return true, "role on clean path"
		}
		return false, "not in usernames whitelist"
	default:
		return true, "candidate"
	}
}

// IsBlockedEmail is kept for callers; prefer IsCandidate / Finalize.
func (c *Config) IsBlockedEmail(localPart, domain, filePath string) (bool, string) {
	ok, reason := c.ShouldKeepEmail(localPart, domain, filePath)
	return !ok, reason
}

// Collector accumulates unique candidate emails across a scan (thread-safe).
type Collector struct {
	mu     sync.Mutex
	emails map[string]struct{}
	inApp  map[string]bool // seen at least once under AppRoots
	cfg    *Config
}

// DomainCount is a domain with how many kept emails it contributed.
type DomainCount struct {
	Domain string
	Count  int
}

func NewCollector(cfg *Config) *Collector {
	return &Collector{
		emails: make(map[string]struct{}),
		inApp:  make(map[string]bool),
		cfg:    cfg,
	}
}

// Add records a candidate email. filePath decides AppRoot boost membership.
func (c *Collector) Add(email, filePath string) {
	if c == nil {
		return
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return
	}
	underApp := false
	if c.cfg != nil {
		underApp = c.cfg.IsUnderAppRoot(filePath)
	}
	c.mu.Lock()
	c.emails[email] = struct{}{}
	if underApp {
		c.inApp[email] = true
	}
	c.mu.Unlock()
}

func (c *Collector) CandidateCount() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.emails)
}

func (c *Collector) Count() int {
	return len(c.Finalize())
}

// Finalize applies mode-specific selection for ModeFiltered:
// group candidates by domain; keep a domain's emails only when that domain has
// at least MinDomainEmailCount distinct addresses (default 2).
// Lone role usernames are NOT kept by themselves (use --email-mode=roles for that).
// AppRoots still matter for Stage-1 path filtering (OS excludes vs nested junk),
// but do not bypass the domain-count rule.
func (c *Collector) Finalize() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	cfg := c.cfg
	if cfg == nil || cfg.Mode != ModeFiltered {
		out := make([]string, 0, len(c.emails))
		for e := range c.emails {
			out = append(out, e)
		}
		sort.Strings(out)
		return out
	}

	minCount := cfg.MinDomainEmailCount
	if minCount < 2 {
		minCount = 2
	}

	byDomain := map[string]map[string]struct{}{}
	for email := range c.emails {
		_, domain, ok := SplitEmail(email)
		if !ok {
			continue
		}
		if byDomain[domain] == nil {
			byDomain[domain] = map[string]struct{}{}
		}
		byDomain[domain][email] = struct{}{}
	}

	keepDomain := map[string]struct{}{}
	for domain, emails := range byDomain {
		if len(emails) >= minCount {
			keepDomain[domain] = struct{}{}
		}
	}

	kept := map[string]struct{}{}
	for email := range c.emails {
		_, domain, ok := SplitEmail(email)
		if !ok {
			continue
		}
		if _, ok := keepDomain[domain]; ok {
			kept[email] = struct{}{}
		}
	}

	out := make([]string, 0, len(kept))
	for e := range kept {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// DomainStats returns kept domains ordered by email count (desc).
func (c *Collector) DomainStats() []DomainCount {
	final := c.Finalize()
	counts := map[string]int{}
	for _, email := range final {
		_, domain, ok := SplitEmail(email)
		if !ok {
			continue
		}
		counts[domain]++
	}
	out := make([]DomainCount, 0, len(counts))
	for d, n := range counts {
		out = append(out, DomainCount{Domain: d, Count: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Count > out[j].Count
	})
	return out
}

// UniqueSorted returns finalized unique emails sorted alphabetically.
func (c *Collector) UniqueSorted() []string {
	return c.Finalize()
}

// CommaSeparated returns finalized unique emails as a CSV string.
func (c *Collector) CommaSeparated() string {
	return strings.Join(c.Finalize(), ",")
}
