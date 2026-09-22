package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestQANormalizeAcceptance(t *testing.T) {
	ok := map[string]string{
		"http://GOOGLE.com/":         "google.com",
		" https://WWW.Google.co.il/": "www.google.co.il",
		"GOOGLE.COM.":                "google.com",
		"google.com./":               "google.com",
		"WWW.GOOGLE.COM":             "www.google.com",
		"www.google.co.il.":          "www.google.co.il",
		"münchen.de":                 "xn--mnchen-3ya.de",
		"http://пример.рф/":          "xn--e1afmkfd.xn--p1ai",
	}
	for in, want := range ok {
		if got, err := NormalizeDomain(in); err != nil || got != want {
			t.Errorf("NormalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"google.com/search", "http://GOOGLE.com/search", "https://www.google.com/search?q=x", "google.com/search/"} {
		if _, err := NormalizeDomain(in); !errors.Is(err, ErrDomainHasPath) {
			t.Errorf("NormalizeDomain(%q) err = %v, want ErrDomainHasPath", in, err)
		}
	}
}

func TestQASaveReloadPreservesRules(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	c := mustLoad(t, LoadOptions{Path: p})
	block := []DomainRule{
		{"google.com", false},
		{"www.google.com", false},
		{"google.co.il", false},
		{"www.google.co.il", false},
		{"example.com", true},
	}
	allow := []DomainRule{{"mail.google.com", false}, {"docs.example.com", true}}
	for _, r := range block {
		if err := c.UpsertBlockRule(r); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range allow {
		if err := c.UpsertAllowRule(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c2 := mustLoad(t, LoadOptions{Path: p})
	if got := c2.GetBlockRules(); !reflect.DeepEqual(got, block) {
		t.Fatalf("block after reload = %+v", got)
	}
	if got := c2.GetAllowRules(); !reflect.DeepEqual(got, allow) {
		t.Fatalf("allow after reload = %+v", got)
	}
	if d := c2.Diagnostics(); d.Source != "current" || d.MigratedFrom != "" || len(d.SkippedRules) != 0 {
		t.Fatalf("diagnostics = %+v", d)
	}
	// a removed rule stays removed across reload
	if !c2.RemoveBlockRule("www.google.com") || c2.Save() != nil {
		t.Fatal("remove+save failed")
	}
	c3 := mustLoad(t, LoadOptions{Path: p})
	if blocks(c3, "www.google.com") || !blocks(c3, "google.com") || blocks(c3, "mail.google.com") {
		t.Fatalf("after remove: %+v", c3.GetBlockRules())
	}
}

func checkV2Skipped(t *testing.T, c *Config) {
	t.Helper()
	if got := c.Diagnostics().SkippedLegacy; !reflect.DeepEqual(got, []string{"not a domain", "example.io/path"}) {
		t.Fatalf("skipped = %v", got)
	}
}

func checkV2Fixture(t *testing.T, c *Config) {
	t.Helper()
	wantBlock := []DomainRule{{"example.com", true}, {"www.example.net", true}, {"example.org", true}}
	if got := c.GetBlockRules(); !reflect.DeepEqual(got, wantBlock) {
		t.Fatalf("block = %+v", got)
	}
	wantAllow := []DomainRule{{"mail.google.com", false}, {"docs.google.com", false}}
	if got := c.GetAllowRules(); !reflect.DeepEqual(got, wantAllow) {
		t.Fatalf("allow = %+v", got)
	}
	if c.PasswordHash != "$2a$10$v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v2v" || c.ProxyPort != 8181 || c.AutoStart {
		t.Fatal("system settings lost")
	}
	if !c.BlockAdultContent || !c.BlockImageSearch || c.BlockYouTube || c.SafeSearch {
		t.Fatal("content toggles lost")
	}
	if c.DisableDelayHours != 2 || c.DisableRequestedAt == nil || !c.DisableRequestedAt.Equal(time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)) {
		t.Fatal("disable delay lost")
	}
	if c.BlockedMessage != "Custom message kept by the user." {
		t.Fatalf("custom message changed: %q", c.BlockedMessage)
	}
	if got := c.GetUserKeywords(); !reflect.DeepEqual(got, []string{"kw1", "kw2"}) {
		t.Fatalf("keywords = %v", got)
	}
	if c.Stats.TotalBlocked != 7 || len(c.Stats.TopBlocked) != 1 || c.Stats.TopBlocked[0].Count != 5 {
		t.Fatalf("stats = %+v", c.Stats)
	}
	if blocks(c, "google.com") || !blocks(c, "a.example.com") || !allows(c, "mail.google.com") || allows(c, "x.mail.google.com") {
		t.Fatal("V2 rule semantics changed")
	}
}

func TestQAV2FixtureInPlace(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "v2_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	writeFile(t, p, string(raw))
	c := mustLoad(t, LoadOptions{Path: p})
	checkV2Fixture(t, c)
	checkV2Skipped(t, c)
	d := c.Diagnostics()
	if d.SchemaVersion != 2 || d.BackupPath != p+".v2.bak" || d.LoadErr != "" || c.ReadOnly() {
		t.Fatalf("diagnostics = %+v", d)
	}
	if readFile(t, p+".v2.bak") != string(raw) {
		t.Fatal("backup differs from original")
	}
	var disk map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, p)), &disk); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"userBlocklist", "userAllowlist"} {
		if _, ok := disk[k]; ok {
			t.Fatalf("%s still on disk", k)
		}
	}
	c2 := mustLoad(t, LoadOptions{Path: p})
	checkV2Fixture(t, c2)
	if c2.Diagnostics().MigratedFrom != "" {
		t.Fatal("migrated twice")
	}
}

func TestQAV2FixtureFromLegacyPath(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "v2_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cur := filepath.Join(dir, "cur", "config.json")
	leg := filepath.Join(dir, "K9WebProtection", "config.json")
	writeFile(t, leg, "\xEF\xBB\xBF"+string(raw))
	c := mustLoad(t, LoadOptions{Path: cur, LegacyPaths: []string{leg}})
	checkV2Fixture(t, c)
	checkV2Skipped(t, c)
	if readFile(t, leg) != "\xEF\xBB\xBF"+string(raw) {
		t.Fatal("legacy file modified")
	}
	checkV2Fixture(t, mustLoad(t, LoadOptions{Path: cur, LegacyPaths: []string{leg}}))
}

func TestQASaveFailureKeepsMemoryAndRecovers(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	c := mustLoad(t, LoadOptions{Path: p})
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	c.UpsertBlockRule(DomainRule{Domain: "google.com"})
	if err := c.Save(); err == nil {
		t.Fatal("Save onto a directory should fail")
	}
	if !blocks(c, "google.com") || c.ReadOnly() {
		t.Fatal("failed save must not drop in-memory rules")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(); err != nil {
		t.Fatalf("retry after fixing the target: %v", err)
	}
	if got := mustLoad(t, LoadOptions{Path: p}).GetBlockRules(); !reflect.DeepEqual(got, []DomainRule{{"google.com", false}}) {
		t.Fatalf("reloaded = %+v", got)
	}
}
