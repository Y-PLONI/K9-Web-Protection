package config

import (
	"errors"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  error
	}{
		{"google.com", "google.com", nil},
		{"  Google.COM  ", "google.com", nil},
		{"google.com.", "google.com", nil},
		{"https://google.com", "google.com", nil},
		{"HTTP://google.com/", "google.com", nil},
		{"google.com/", "google.com", nil},
		{"www.google.com", "www.google.com", nil},
		{"mail.google.com", "mail.google.com", nil},
		{"bücher.de", "xn--bcher-kva.de", nil},
		{"BÜCHER.de", "xn--bcher-kva.de", nil},
		{"xn--bcher-kva.de", "xn--bcher-kva.de", nil},
		{"google.com/search", "", ErrDomainHasPath},
		{"https://google.com/search?q=1", "", ErrDomainHasPath},
		{"google.com?q=1", "", ErrDomainHasPath},
		{"google.com#top", "", ErrDomainHasPath},
		{"google.com//", "", ErrDomainHasPath},
		{"google.com:443", "", ErrInvalidDomain},
		{"user@google.com", "", ErrInvalidDomain},
		{"https://user:pw@google.com", "", ErrInvalidDomain},
		{"", "", ErrInvalidDomain},
		{"   ", "", ErrInvalidDomain},
		{"https://", "", ErrInvalidDomain},
		{"goo gle.com", "", ErrInvalidDomain},
		{"google", "", ErrInvalidDomain},
		{"google..com", "", ErrInvalidDomain},
		{".google.com", "", ErrInvalidDomain},
		{"-google.com", "", ErrInvalidDomain},
		{"goo_gle.com", "", ErrInvalidDomain},
		{"*.google.com", "", ErrInvalidDomain},
		{"1.2.3.4", "", ErrInvalidDomain},
		{"123.456", "", ErrInvalidDomain},
		{"[::1]", "", ErrInvalidDomain},
	}
	for _, tc := range cases {
		got, err := NormalizeDomain(tc.in)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("NormalizeDomain(%q) err = %v, want %v", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestParseRule(t *testing.T) {
	r, err := ParseRule("*.Example.com", false)
	if err != nil || r != (DomainRule{"example.com", true}) {
		t.Fatalf("wildcard: %+v %v", r, err)
	}
	r, err = ParseRule("https://example.com/", false)
	if err != nil || r != (DomainRule{"example.com", false}) {
		t.Fatalf("exact: %+v %v", r, err)
	}
	r, err = ParseRule("example.com", true)
	if err != nil || r != (DomainRule{"example.com", true}) {
		t.Fatalf("include flag: %+v %v", r, err)
	}
	for _, in := range []string{"*.", "*", "**.x.com", "*x.com", "*.x.com/path"} {
		if _, err := ParseRule(in, false); err == nil {
			t.Errorf("ParseRule(%q) should fail", in)
		}
	}
}

func TestMatches(t *testing.T) {
	exact := DomainRule{Domain: "google.com"}
	sub := DomainRule{Domain: "google.com", IncludeSubdomains: true}
	www := DomainRule{Domain: "www.google.com"}
	cases := []struct {
		r    DomainRule
		host string
		want bool
	}{
		{exact, "google.com", true},
		{exact, "GOOGLE.com.", true},
		{exact, "mail.google.com", false},
		{exact, "www.google.com", false},
		{sub, "google.com", true},
		{sub, "mail.google.com", true},
		{sub, "a.b.google.com", true},
		{sub, "notgoogle.com", false},
		{sub, "google.com.evil.net", false},
		{sub, ".google.com", false},
		{www, "www.google.com", true},
		{www, "google.com", false},
		{DomainRule{}, "", false},
	}
	for _, tc := range cases {
		if got := tc.r.Matches(tc.host); got != tc.want {
			t.Errorf("%+v.Matches(%q) = %v, want %v", tc.r, tc.host, got, tc.want)
		}
	}
}

func TestUpsertRemoveRules(t *testing.T) {
	c := newConfig("")
	if err := c.UpsertBlockRule(DomainRule{Domain: "Google.com"}); err != nil {
		t.Fatal(err)
	}
	if err := c.UpsertBlockRule(DomainRule{Domain: "https://google.com/", IncludeSubdomains: true}); err != nil {
		t.Fatal(err)
	}
	if got := c.GetBlockRules(); len(got) != 1 || got[0] != (DomainRule{"google.com", true}) {
		t.Fatalf("upsert keyed by normalized domain: %+v", got)
	}
	if err := c.UpsertBlockRule(DomainRule{Domain: "google.com/x"}); !errors.Is(err, ErrDomainHasPath) {
		t.Fatalf("invalid upsert err = %v", err)
	}
	if !c.RemoveBlockRule("GOOGLE.COM.") || len(c.GetBlockRules()) != 0 {
		t.Fatal("remove by normalized domain failed")
	}
	if c.RemoveBlockRule("google.com") {
		t.Fatal("second remove should report false")
	}

	c.UpsertAllowRule(DomainRule{Domain: "www.google.com"})
	c.UpsertAllowRule(DomainRule{Domain: "google.com"})
	if got := c.GetAllowRules(); len(got) != 2 {
		t.Fatalf("www must be its own rule: %+v", got)
	}
	got := c.GetAllowRules()
	got[0].Domain = "mutated"
	if c.GetAllowRules()[0].Domain == "mutated" {
		t.Fatal("GetAllowRules must return a copy")
	}
}

func anyMatch(rules []DomainRule, host string) bool {
	for _, r := range rules {
		if r.Matches(host) {
			return true
		}
	}
	return false
}

func blocks(c *Config, host string) bool { return anyMatch(c.GetBlockRules(), host) }

func allows(c *Config, host string) bool { return anyMatch(c.GetAllowRules(), host) }

func TestPolicyViewAndUpdate(t *testing.T) {
	c := newConfig("")
	c.UpsertBlockRule(DomainRule{Domain: "example.com", IncludeSubdomains: true})
	c.Update(func(c *Config) {
		c.SafeSearch = false
		c.FilterLevel = "custom"
		c.UserKeywords = []string{"kw"}
	})
	v := c.PolicyView()
	if v.SafeSearch || v.FilterLevel != "custom" || v.ProxyPort != 8080 || len(v.Block) != 1 || len(v.Keywords) != 1 {
		t.Fatalf("unexpected view %+v", v)
	}
	v.Block[0].Domain = "mutated"
	v.Keywords[0] = "mutated"
	if c.GetBlockRules()[0].Domain != "example.com" || c.GetUserKeywords()[0] != "kw" {
		t.Fatal("PolicyView must return copies")
	}
}

func TestAddBlockRuleRefusesNarrowing(t *testing.T) {
	c := newConfig("")
	if _, err := c.AddBlockRule(DomainRule{Domain: "*.google.com"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.AddBlockRule(DomainRule{Domain: "Google.com"}); !errors.Is(err, ErrNarrowing) {
		t.Fatalf("narrowing err = %v", err)
	}
	if r, err := c.AddBlockRule(DomainRule{Domain: "www.google.com"}); err != nil || r.Domain != "www.google.com" {
		t.Fatalf("%+v %v", r, err)
	}
	if got := c.GetBlockRules(); len(got) != 2 || !got[0].IncludeSubdomains {
		t.Fatalf("rules = %+v", got)
	}
}
