package proxy

import (
	"net"
	"strings"
)

type Rule struct {
	Host              string
	IncludeSubdomains bool
}

type Policy struct {
	Block, Allow      []Rule
	FilterLevel       string
	BlockAdultContent bool
	BlockImageSearch  bool
	BlockYouTube      bool
	SafeSearch        bool
	Keywords          []string
	Focus             func(host string) bool
}

// CanonicalHost lowercases and strips the port, IPv6 brackets and trailing dots.
func CanonicalHost(hostport string) string {
	h := strings.TrimSpace(hostport)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	} else if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = h[1 : len(h)-1]
	}
	return strings.TrimRight(strings.ToLower(h), ".")
}

func MatchRule(host string, r Rule) bool {
	return matchCanonical(CanonicalHost(host), Rule{Host: CanonicalHost(r.Host), IncludeSubdomains: r.IncludeSubdomains})
}

func matchCanonical(host string, r Rule) bool {
	if host == "" || r.Host == "" {
		return false
	}
	return host == r.Host || r.IncludeSubdomains && strings.HasSuffix(host, "."+r.Host)
}

// matchAny expects rules already canonicalized by clonePolicy.
func matchAny(host string, rules []Rule) bool {
	h := CanonicalHost(host)
	for _, r := range rules {
		if matchCanonical(h, r) {
			return true
		}
	}
	return false
}

func (pol *Policy) allows(host string) bool { return matchAny(host, pol.Allow) }

func (pol *Policy) blocks(host string) bool { return matchAny(host, pol.Block) }

func (pol *Policy) focusBlocks(host string) bool { return pol.Focus != nil && pol.Focus(host) }

func (pol *Policy) keywordMatch(target string) bool {
	t := strings.ToLower(target)
	for _, kw := range pol.Keywords {
		if kw != "" && strings.Contains(t, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

func clonePolicy(pol Policy) Policy {
	c := pol
	c.Block = canonicalRules(pol.Block)
	c.Allow = canonicalRules(pol.Allow)
	c.Keywords = append([]string(nil), pol.Keywords...)
	return c
}

func canonicalRules(in []Rule) []Rule {
	var out []Rule
	for _, r := range in {
		if h := CanonicalHost(r.Host); h != "" {
			out = append(out, Rule{Host: h, IncludeSubdomains: r.IncludeSubdomains})
		}
	}
	return out
}
