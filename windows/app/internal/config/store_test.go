package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestMain points the profile at a temp dir so no test can reach the real settings.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "k10-config-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, k := range []string{"USERPROFILE", "HOME", "APPDATA"} {
		os.Setenv(k, dir)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const customHash = "$2a$10$customcustomcustomcustomcustomcustomcustomcustomcust"

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func mustLoad(t *testing.T, o LoadOptions) *Config {
	t.Helper()
	if o.LegacyPaths == nil {
		o.LegacyPaths = []string{}
	}
	c, err := LoadWith(o)
	if err != nil {
		t.Fatalf("LoadWith: %v", err)
	}
	return c
}

func TestLoadMissingUsesDefaults(t *testing.T) {
	dir := t.TempDir()
	c := mustLoad(t, LoadOptions{Path: filepath.Join(dir, "config.json")})
	d := c.Diagnostics()
	if c.ReadOnly() || c.PasswordHash != defaultPasswordHash || d.Source != "default" || c.SettingsVersion != SchemaVersion {
		t.Fatalf("unexpected defaults: ro=%v src=%q v=%d", c.ReadOnly(), d.Source, c.SettingsVersion)
	}
	if len(dirNames(t, dir)) != 0 {
		t.Fatal("loading defaults must not write files")
	}
}

func TestLoadWithBOM(t *testing.T) {
	for _, bom := range []string{"", "\xEF\xBB\xBF"} {
		dir := t.TempDir()
		p := filepath.Join(dir, "config.json")
		writeFile(t, p, bom+`{"settingsVersion":3,"passwordHash":"`+customHash+`","blockRules":[{"domain":"example.com","includeSubdomains":true}]}`)
		c := mustLoad(t, LoadOptions{Path: p})
		if c.PasswordHash != customHash || !blocks(c, "a.example.com") {
			t.Fatalf("bom=%q: not loaded", bom)
		}
	}
}

func TestCorruptFailsClosed(t *testing.T) {
	inputs := []string{
		`{"passwordHash":"` + customHash + `","userBlocklist":["a.com"`,
		`{"passwordHash":"` + customHash + `","proxyPort":"not a number"}`,
		`null`,
		``,
		"\xEF\xBB\xBF",
	}
	for i, in := range inputs {
		dir := t.TempDir()
		p := filepath.Join(dir, "config.json")
		writeFile(t, p, in)
		c, err := LoadWith(LoadOptions{Path: p, LegacyPaths: []string{}})
		var le *LoadError
		if !errors.As(err, &le) || le.Path != p {
			t.Fatalf("case %d: want LoadError for %s, got %v", i, p, err)
		}
		if c == nil || !c.ReadOnly() || c.Diagnostics().LoadErr == "" {
			t.Fatalf("case %d: config must be read-only with diagnostics", i)
		}
		if c.PasswordHash == defaultPasswordHash || c.PasswordHash == customHash {
			t.Fatalf("case %d: password hash must be neither default nor partially decoded: %q", i, c.PasswordHash)
		}
		if !c.BlockAdultContent || !c.SafeSearch {
			t.Fatalf("case %d: protective defaults expected", i)
		}
		if err := c.Save(); !errors.Is(err, ErrReadOnly) {
			t.Fatalf("case %d: Save err = %v, want ErrReadOnly", i, err)
		}
		if got := readFile(t, p); got != in {
			t.Fatalf("case %d: corrupt file modified", i)
		}
		if names := dirNames(t, dir); len(names) != 1 {
			t.Fatalf("case %d: unexpected files %v", i, names)
		}
	}
}

func TestNewerSchemaLoadsReadOnly(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	in := `{"settingsVersion":4,"futureField":{"x":1},"passwordHash":"` + customHash + `","blockRules":[{"domain":"example.com","includeSubdomains":true}]}`
	writeFile(t, p, in)
	c := mustLoad(t, LoadOptions{Path: p})
	if !c.ReadOnly() || c.Diagnostics().LoadErr == "" || c.Diagnostics().SchemaVersion != 4 {
		t.Fatalf("newer schema must load read-only with diagnostics: %+v", c.Diagnostics())
	}
	if c.PasswordHash != customHash || !blocks(c, "a.example.com") {
		t.Fatal("known settings should still be read")
	}
	c.UpsertBlockRule(DomainRule{Domain: "other.com"})
	if err := c.Save(); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Save err = %v, want ErrReadOnly", err)
	}
	if readFile(t, p) != in {
		t.Fatal("newer file must not be rewritten")
	}
	if names := dirNames(t, dir); len(names) != 1 {
		t.Fatalf("unexpected files %v", names)
	}
}

func TestCorruptLegacyFailsClosed(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "new", "config.json")
	leg := filepath.Join(dir, "old", "config.json")
	writeFile(t, leg, `{"passwordHash":`)
	c, err := LoadWith(LoadOptions{Path: cur, LegacyPaths: []string{leg}})
	var le *LoadError
	if !errors.As(err, &le) || le.Path != leg || !c.ReadOnly() {
		t.Fatalf("want read-only LoadError for legacy, got %v", err)
	}
	if _, err := os.Stat(cur); !os.IsNotExist(err) {
		t.Fatal("current file must not be created")
	}
}

func TestMigrateUnversionedCurrent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	orig := `{"userBlocklist":["example.com","example.com","bad:1"],"userAllowlist":["mail.google.com","*.docs.google.com"],"userKeywords":["kw"],"passwordHash":"` + customHash + `","safeSearch":false}`
	writeFile(t, p, orig)

	c := mustLoad(t, LoadOptions{Path: p})
	if got := c.GetBlockRules(); len(got) != 1 || got[0] != (DomainRule{"example.com", true}) {
		t.Fatalf("block rules = %+v", got)
	}
	want := []DomainRule{{"mail.google.com", false}, {"docs.google.com", true}}
	if got := c.GetAllowRules(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("allow rules = %+v", got)
	}
	if c.PasswordHash != customHash || c.SafeSearch || c.GetUserKeywords()[0] != "kw" {
		t.Fatal("other settings must survive migration")
	}
	d := c.Diagnostics()
	bak := p + ".v2.bak"
	if d.MigratedFrom != p || d.BackupPath != bak || d.SchemaVersion != 2 || d.LoadErr != "" {
		t.Fatalf("diagnostics = %+v", d)
	}
	if len(d.SkippedLegacy) != 1 || d.SkippedLegacy[0] != "bad:1" {
		t.Fatalf("skipped = %v", d.SkippedLegacy)
	}
	if readFile(t, bak) != orig {
		t.Fatal("backup must hold the original bytes")
	}

	var disk map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, p)), &disk); err != nil {
		t.Fatal(err)
	}
	if string(disk["settingsVersion"]) != "3" {
		t.Fatalf("settingsVersion on disk = %s", disk["settingsVersion"])
	}
	if _, ok := disk["userBlocklist"]; ok {
		t.Fatal("legacy fields must be cleared on disk")
	}
	if _, ok := disk["userAllowlist"]; ok {
		t.Fatal("legacy fields must be cleared on disk")
	}

	c2 := mustLoad(t, LoadOptions{Path: p})
	if c2.Diagnostics().MigratedFrom != "" || len(c2.GetBlockRules()) != 1 {
		t.Fatal("second load must not migrate again")
	}
}

func TestMigrationBackupNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	bak := p + ".v2.bak"
	writeFile(t, bak, "earlier backup")
	writeFile(t, p, `{"userBlocklist":["example.com"]}`)
	c := mustLoad(t, LoadOptions{Path: p})
	if readFile(t, bak) != "earlier backup" {
		t.Fatal("existing backup overwritten")
	}
	if c.Diagnostics().BackupPath != bak {
		t.Fatal("backup path should point at the existing backup")
	}
	if names := dirNames(t, dir); len(names) != 2 {
		t.Fatalf("unexpected files %v", names)
	}
}

func TestLegacyCopy(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "new", "config.json")
	leg := filepath.Join(dir, "K9WebProtection", "config.json")
	v2 := "\xEF\xBB\xBF" + `{
  "userBlocklist": ["example.com"],
  "userAllowlist": ["mail.google.com"],
  "userKeywords": [],
  "blockAdultContent": true,
  "blockImageSearch": false,
  "blockYouTube": true,
  "safeSearch": true,
  "disableDelayHours": 0,
  "blockedMessage": "This website has been blocked to help you stay focused and protected.",
  "focusModeUntil": "0001-01-01T00:00:00Z",
  "passwordHash": "` + customHash + `",
  "proxyPort": 8080,
  "autoStart": true,
  "stats": {"totalBlocked": 3, "blockedToday": 1, "lastReset": "2024-01-01T00:00:00Z", "topBlocked": [{"domain": "example.com", "count": 3}]}
}`
	writeFile(t, leg, v2)

	c := mustLoad(t, LoadOptions{Path: cur, LegacyPaths: []string{"", cur, leg}})
	d := c.Diagnostics()
	if d.Source != "legacy" || d.MigratedFrom != leg || d.BackupPath != "" || d.SchemaVersion != 2 {
		t.Fatalf("diagnostics = %+v", d)
	}
	if c.PasswordHash != customHash || !c.BlockYouTube || c.Stats.TotalBlocked != 3 {
		t.Fatal("V2 settings not carried over")
	}
	if !blocks(c, "www.example.com") || !allows(c, "mail.google.com") || allows(c, "x.mail.google.com") {
		t.Fatal("V2 rule semantics not preserved")
	}
	if readFile(t, leg) != v2 {
		t.Fatal("legacy file must never be modified")
	}
	if names := dirNames(t, filepath.Dir(leg)); len(names) != 1 {
		t.Fatalf("nothing may be written next to the legacy file: %v", names)
	}
	c2 := mustLoad(t, LoadOptions{Path: cur})
	if c2.PasswordHash != customHash || c2.SettingsVersion != SchemaVersion || len(c2.GetBlockRules()) != 1 {
		t.Fatal("copied config not persisted at the current path")
	}
}

func TestLegacyIgnoredWhenCurrentExists(t *testing.T) {
	dir := t.TempDir()
	cur := filepath.Join(dir, "new", "config.json")
	leg := filepath.Join(dir, "old", "config.json")
	writeFile(t, cur, `{"settingsVersion":3,"blockRules":[{"domain":"current.com","includeSubdomains":false}]}`)
	writeFile(t, leg, `{"userBlocklist":["legacy.com"],"passwordHash":"`+customHash+`"}`)
	c := mustLoad(t, LoadOptions{Path: cur, LegacyPaths: []string{leg}})
	if c.Diagnostics().Source != "current" || blocks(c, "legacy.com") || !blocks(c, "current.com") || c.PasswordHash == customHash {
		t.Fatal("legacy file must be ignored when current exists")
	}
}

func TestV3RulesNormalizedOnLoad(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	writeFile(t, p, `{"settingsVersion":3,"blockRules":[{"domain":"Example.COM","includeSubdomains":false},{"domain":"example.com","includeSubdomains":true},{"domain":"bad/path","includeSubdomains":true}],"allowRules":null}`)
	c := mustLoad(t, LoadOptions{Path: p})
	if got := c.GetBlockRules(); len(got) != 1 || got[0] != (DomainRule{"example.com", true}) {
		t.Fatalf("block rules = %+v", got)
	}
	if got := c.Diagnostics().SkippedRules; len(got) != 1 {
		t.Fatalf("skipped rules = %v", got)
	}
	if c.GetAllowRules() == nil {
		t.Fatal("rules should be non-nil")
	}
	if names := dirNames(t, dir); len(names) != 1 {
		t.Fatalf("v3 load must not create backups: %v", names)
	}
}

func TestSaveRoundTripAndNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "config.json")
	c := mustLoad(t, LoadOptions{Path: p})
	c.UpsertBlockRule(DomainRule{Domain: "example.com", IncludeSubdomains: true})
	c.UpsertAllowRule(DomainRule{Domain: "www.google.com"})
	for i := 0; i < 5; i++ {
		if err := c.Save(); err != nil {
			t.Fatal(err)
		}
	}
	if names := dirNames(t, filepath.Dir(p)); len(names) != 1 || names[0] != "config.json" {
		t.Fatalf("leftover files: %v", names)
	}
	c2 := mustLoad(t, LoadOptions{Path: p})
	if c2.SettingsVersion != SchemaVersion || len(c2.GetBlockRules()) != 1 || c2.GetAllowRules()[0].Domain != "www.google.com" {
		t.Fatal("round trip failed")
	}
	if strings.Contains(readFile(t, p), "userBlocklist") {
		t.Fatal("legacy keys must not be written")
	}
}

func TestSaveFailsWhenTargetIsDirectory(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	c := mustLoad(t, LoadOptions{Path: p})
	if err := os.Mkdir(p, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(p, "keep"), "x")
	if err := c.Save(); err == nil {
		t.Fatal("Save onto a directory should fail")
	}
	if st, err := os.Stat(p); err != nil || !st.IsDir() || readFile(t, filepath.Join(p, "keep")) != "x" {
		t.Fatal("target must be left intact")
	}
	if names := dirNames(t, dir); len(names) != 1 {
		t.Fatalf("temp file left behind: %v", names)
	}
}

func TestSaveFailsOnReadOnlyTarget(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("rename over a read-only file only fails on Windows")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	orig := `{"settingsVersion":3,"passwordHash":"` + customHash + `"}`
	writeFile(t, p, orig)
	c := mustLoad(t, LoadOptions{Path: p})
	if err := os.Chmod(p, 0400); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(p, 0600)
	c.UpsertBlockRule(DomainRule{Domain: "example.com"})
	if err := c.Save(); err == nil {
		t.Fatal("Save over a read-only file should fail")
	}
	if readFile(t, p) != orig {
		t.Fatal("original must be intact")
	}
	if names := dirNames(t, dir); len(names) != 1 {
		t.Fatalf("temp file left behind: %v", names)
	}
}

func TestConcurrentSaves(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	c := mustLoad(t, LoadOptions{Path: p})
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 15; i++ {
				c.UpsertBlockRule(DomainRule{Domain: fmt.Sprintf("s%d-%d.example.com", g, i)})
				c.Update(func(c *Config) { c.ProxyPort = 8000 + g })
				_ = c.PolicyView()
				_ = blocks(c, "x.example.com")
				if err := c.Save(); err != nil {
					errs <- err
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if names := dirNames(t, dir); len(names) != 1 {
		t.Fatalf("leftover files: %v", names)
	}
	c2 := mustLoad(t, LoadOptions{Path: p})
	if len(c2.GetBlockRules()) != 8*15 {
		t.Fatalf("got %d rules", len(c2.GetBlockRules()))
	}
	if !bytes.Contains([]byte(readFile(t, p)), []byte(`"settingsVersion": 3`)) {
		t.Fatal("settingsVersion missing")
	}
}

func TestDefaultPathIsolatedInTests(t *testing.T) {
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(DefaultPath(), os.TempDir()) || !strings.HasPrefix(home, os.TempDir()) {
		t.Fatalf("tests must not resolve the real profile: %s", DefaultPath())
	}
}

func TestMigrationBackupFailureIsReadOnly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	orig := `{"userBlocklist":["example.com"],"passwordHash":"` + customHash + `"}`
	writeFile(t, p, orig)
	old := backupFn
	backupFn = func(string, []byte) (string, error) { return "", errors.New("disk full") }
	defer func() { backupFn = old }()

	c := mustLoad(t, LoadOptions{Path: p})
	if !c.ReadOnly() || c.LoadFailed() {
		t.Fatalf("readOnly=%v loadFailed=%v", c.ReadOnly(), c.LoadFailed())
	}
	if d := c.Diagnostics(); !strings.Contains(d.LoadErr, "disk full") || d.BackupPath != "" {
		t.Fatalf("diagnostics = %+v", d)
	}
	if err := c.Save(); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Save = %v", err)
	}
	if readFile(t, p) != orig {
		t.Fatal("unbacked-up file overwritten")
	}
	if got := c.GetBlockRules(); len(got) != 1 || c.PasswordHash != customHash {
		t.Fatal("the migrated settings must still be in effect")
	}
}

func TestLoadFailedOnlyForUnreadableFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, p, `{"blockRules":[`)
	c, err := LoadWith(LoadOptions{Path: p, LegacyPaths: []string{}})
	if err == nil || !c.LoadFailed() || !c.ReadOnly() {
		t.Fatalf("corrupt: err=%v loadFailed=%v", err, c.LoadFailed())
	}
	writeFile(t, p, `{"settingsVersion":99}`)
	if c := mustLoad(t, LoadOptions{Path: p}); c.LoadFailed() || !c.ReadOnly() {
		t.Fatal("a newer file is read-only but was read")
	}
}
