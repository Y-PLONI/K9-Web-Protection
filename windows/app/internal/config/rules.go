package config

import (
	"errors"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

type DomainRule struct {
	Domain            string `json:"domain"`
	IncludeSubdomains bool   `json:"includeSubdomains"`
}

var (
	ErrInvalidDomain = errors.New("invalid domain")
	ErrDomainHasPath = errors.New("domain must not include a path")
	ErrReadOnly      = errors.New("config is read-only")
	ErrNarrowing     = errors.New("rule would narrow an existing subdomain rule")
)

func NormalizeDomain(in string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(in))
	if i := strings.Index(s, "://"); i > 0 && isScheme(s[:i]) {
		s = s[i+3:]
	}
	s = strings.TrimSuffix(s, "/")
	if s == "" {
		return "", ErrInvalidDomain
	}
	if strings.ContainsAny(s, "/?#") {
		return "", ErrDomainHasPath
	}
	if strings.ContainsAny(s, "@:[]\\*") || strings.IndexFunc(s, unicode.IsSpace) >= 0 {
		return "", ErrInvalidDomain
	}
	s = strings.TrimSuffix(s, ".")
	a, err := idna.Lookup.ToASCII(s)
	if err != nil || !validHostname(a) {
		return "", ErrInvalidDomain
	}
	return a, nil
}

func ParseRule(in string, includeSub bool) (DomainRule, error) {
	s := strings.TrimSpace(in)
	if strings.HasPrefix(s, "*.") {
		s, includeSub = s[2:], true
	}
	d, err := NormalizeDomain(s)
	if err != nil {
		return DomainRule{}, err
	}
	return DomainRule{Domain: d, IncludeSubdomains: includeSub}, nil
}

func (r DomainRule) Matches(host string) bool {
	if r.Domain == "" {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == r.Domain {
		return true
	}
	n := len(host) - len(r.Domain)
	return r.IncludeSubdomains && n > 1 && host[n-1] == '.' && host[n:] == r.Domain
}

func isScheme(s string) bool {
	for i, ch := range s {
		letter := ch >= 'a' && ch <= 'z'
		if !letter && (i == 0 || !(ch >= '0' && ch <= '9' || ch == '+' || ch == '-' || ch == '.')) {
			return false
		}
	}
	return true
}

func validHostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			ch := l[i]
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	// an all-numeric TLD means an IP address or garbage, not a domain
	return strings.Trim(labels[len(labels)-1], "0123456789") != ""
}

func copyRules(rules []DomainRule) []DomainRule {
	out := make([]DomainRule, len(rules))
	copy(out, rules)
	return out
}

func upsertRule(rules []DomainRule, r DomainRule) []DomainRule {
	for i := range rules {
		if rules[i].Domain == r.Domain {
			rules[i] = r
			return rules
		}
	}
	return append(rules, r)
}

func removeRule(rules []DomainRule, domain string) ([]DomainRule, bool) {
	key := strings.ToLower(strings.TrimSpace(domain))
	if r, err := ParseRule(domain, false); err == nil {
		key = r.Domain
	}
	out := make([]DomainRule, 0, len(rules))
	for _, r := range rules {
		if r.Domain != key {
			out = append(out, r)
		}
	}
	return out, len(out) != len(rules)
}

// normalizeRules re-validates rules read from disk; invalid domains are returned as skipped.
func normalizeRules(rules []DomainRule) (out []DomainRule, skipped []string) {
	out = []DomainRule{}
	for _, r := range rules {
		n, err := ParseRule(r.Domain, r.IncludeSubdomains)
		if err != nil {
			skipped = append(skipped, r.Domain)
			continue
		}
		out = upsertRule(out, n)
	}
	return out, skipped
}

func (c *Config) GetBlockRules() []DomainRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return copyRules(c.BlockRules)
}

func (c *Config) GetAllowRules() []DomainRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return copyRules(c.AllowRules)
}

func (c *Config) UpsertBlockRule(r DomainRule) error {
	r, err := ParseRule(r.Domain, r.IncludeSubdomains)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.BlockRules = upsertRule(c.BlockRules, r)
	return nil
}

// AddBlockRule is UpsertBlockRule that refuses to turn a subdomain rule into an exact one.
func (c *Config) AddBlockRule(r DomainRule) (DomainRule, error) {
	r, err := ParseRule(r.Domain, r.IncludeSubdomains)
	if err != nil {
		return r, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.BlockRules {
		if e.Domain == r.Domain && e.IncludeSubdomains && !r.IncludeSubdomains {
			return r, ErrNarrowing
		}
	}
	c.BlockRules = upsertRule(c.BlockRules, r)
	return r, nil
}

func (c *Config) RemoveBlockRule(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ok bool
	c.BlockRules, ok = removeRule(c.BlockRules, domain)
	return ok
}

func (c *Config) UpsertAllowRule(r DomainRule) error {
	r, err := ParseRule(r.Domain, r.IncludeSubdomains)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.AllowRules = upsertRule(c.AllowRules, r)
	return nil
}

func (c *Config) RemoveAllowRule(domain string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	var ok bool
	c.AllowRules, ok = removeRule(c.AllowRules, domain)
	return ok
}

type PolicyView struct {
	FilterLevel       string
	BlockAdultContent bool
	BlockImageSearch  bool
	BlockYouTube      bool
	SafeSearch        bool
	Keywords          []string
	Block, Allow      []DomainRule
	ProxyPort         int
}

func (c *Config) PolicyView() PolicyView {
	c.mu.RLock()
	defer c.mu.RUnlock()
	kw := make([]string, len(c.UserKeywords))
	copy(kw, c.UserKeywords)
	return PolicyView{
		FilterLevel:       c.FilterLevel,
		BlockAdultContent: c.BlockAdultContent,
		BlockImageSearch:  c.BlockImageSearch,
		BlockYouTube:      c.BlockYouTube,
		SafeSearch:        c.SafeSearch,
		Keywords:          kw,
		Block:             copyRules(c.BlockRules),
		Allow:             copyRules(c.AllowRules),
		ProxyPort:         c.ProxyPort,
	}
}

// Update runs fn under the write lock; fn must not call other locking methods.
func (c *Config) Update(fn func(*Config)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	fn(c)
}
