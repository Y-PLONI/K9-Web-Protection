//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"k10webprotection/internal/config"
	"k10webprotection/internal/enforce"
	"k10webprotection/internal/hosts"
	"k10webprotection/internal/i18n"
	"k10webprotection/internal/proxy"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "k10-app-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	proxy.SetCADir(dir) // keep the test CA out of the user's profile
	for _, k := range []string{"USERPROFILE", "HOME", "APPDATA"} {
		os.Setenv(k, dir) // and config.DefaultPath too
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const testPassword = "secret-pw"

// memHosts renders plans into an in-memory hosts file; the real one is never touched.
type memHosts struct {
	mu      sync.Mutex
	content string
	err     error // returned instead of writing, e.g. a declined UAC prompt
	calls   int
}

func (h *memHosts) apply(plan hosts.Plan) (hosts.Result, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	next, res := hosts.Render(h.content, plan)
	if h.err != nil {
		return res, h.err
	}
	h.content = next
	return res, nil
}

func (h *memHosts) active() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Contains(h.content, "# K10-Web-Protection START")
}

func (h *memHosts) names() map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	m := map[string]string{}
	for _, l := range strings.Split(h.content, "\n") {
		if f := strings.Fields(l); len(f) == 2 && !strings.HasPrefix(f[0], "#") {
			m[f[1]] = f[0]
		}
	}
	return m
}

func newTestApp(t *testing.T, cfgPath string) (*App, *memHosts) {
	t.Helper()
	cfg, err := config.LoadWith(config.LoadOptions{Path: cfgPath, LegacyPaths: []string{}})
	if cfg == nil {
		t.Fatal(err)
	}
	if !cfg.ReadOnly() {
		hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Update(func(c *config.Config) { c.PasswordHash = string(hash); c.SafeSearch = false })
	}
	h := &memHosts{content: "127.0.0.1 localhost\r\n"}
	a := NewApp(cfg, err, config.LoadOptions{Path: cfgPath, LegacyPaths: []string{}})
	a.hostsActive = h.active
	a.sysProxy = func(bool) {} // never touch the real system proxy
	a.proxy = proxy.New(0, nil)
	a.applier = enforce.New(cfg, a.proxy, enforce.HostsFunc(h.apply), a.protectionOn)
	atomic.StoreInt32(&a.proxyRunning, 1)
	return a, h
}

func TestQAAppBlockRules(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	a, h := newTestApp(t, p)

	for _, in := range []string{"http://GOOGLE.com/", "WWW.google.com.", "google.co.il", "www.google.co.il"} {
		v, err := a.AddBlockRule(in, false)
		if err != nil || v.Apply.ConfigError != "" || v.Apply.HostsError != "" || !v.Apply.HostsApplied {
			t.Fatalf("AddBlockRule(%q): %+v %v", in, v, err)
		}
	}
	want := []config.DomainRule{{Domain: "google.com"}, {Domain: "www.google.com"}, {Domain: "google.co.il"}, {Domain: "www.google.co.il"}}
	if got := a.GetRules().Block; !reflect.DeepEqual(got, want) {
		t.Fatalf("GetRules().Block = %+v", got)
	}
	for _, host := range []string{"google.com", "www.google.com", "google.co.il", "www.google.co.il"} {
		if !a.proxy.HostBlocked(host) || h.names()[host] != "0.0.0.0" {
			t.Errorf("%s not blocked in proxy+hosts", host)
		}
	}
	for _, host := range []string{"mail.google.com", "accounts.google.com", "drive.google.com", "calendar.google.com"} {
		if a.proxy.HostBlocked(host) {
			t.Errorf("proxy blocks %s", host)
		}
		if _, ok := h.names()[host]; ok {
			t.Errorf("hosts contains %s", host)
		}
	}

	if _, err := a.AddBlockRule("google.com/search", false); err == nil || err.Error() != i18n.T("err.domainHasPath") {
		t.Errorf("path input err = %v", err)
	}
	if _, err := a.AddBlockRule("goo gle.com", false); err == nil || err.Error() != i18n.T("err.invalidDomain") {
		t.Errorf("invalid input err = %v", err)
	}

	// widening is free, narrowing needs the password-checked remove
	if _, err := a.AddBlockRule("*.google.co.il", false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddBlockRule("google.co.il", false); err == nil {
		t.Error("narrowing a subdomain rule must be refused")
	}
	if !a.proxy.HostBlocked("images.google.co.il") {
		t.Error("widened rule not applied")
	}

	if _, err := a.RemoveBlockRule("wrong", "google.com"); err == nil || err.Error() != i18n.T("err.incorrectPassword") {
		t.Errorf("wrong password err = %v", err)
	}
	if !a.proxy.HostBlocked("google.com") {
		t.Fatal("rule removed despite wrong password")
	}
	if _, err := a.RemoveBlockRule(testPassword, "GOOGLE.COM"); err != nil {
		t.Fatal(err)
	}
	if a.proxy.HostBlocked("google.com") || h.names()["google.com"] != "" {
		t.Error("google.com still blocked after remove")
	}
	if _, err := a.RemoveBlockRule(testPassword, "google.com"); err == nil || err.Error() != i18n.T("err.ruleNotFound") {
		t.Errorf("second remove err = %v", err)
	}

	b, _ := newTestApp(t, p)
	want = []config.DomainRule{{Domain: "www.google.com"}, {Domain: "google.co.il", IncludeSubdomains: true}, {Domain: "www.google.co.il"}}
	if got := b.conf().GetBlockRules(); !reflect.DeepEqual(got, want) {
		t.Errorf("reloaded rules = %+v", got)
	}
}

func TestQAAppAllowRules(t *testing.T) {
	a, h := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	if _, err := a.AddBlockRule("*.google.com", false); err != nil {
		t.Fatal(err)
	}
	if !a.proxy.HostBlocked("mail.google.com") {
		t.Fatal("subdomain rule not applied")
	}
	if _, err := a.AddAllowRule("wrong", "mail.google.com", false); err == nil {
		t.Error("allow rule accepted with a wrong password")
	}
	if _, err := a.AddAllowRule(testPassword, "www.google.com", false); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddAllowRule(testPassword, "https://Mail.Google.com/", false); err != nil {
		t.Fatal(err)
	}
	if a.proxy.HostBlocked("mail.google.com") || !a.proxy.HostBlocked("x.mail.google.com") || !a.proxy.HostBlocked("google.com") {
		t.Error("allow precedence wrong in proxy")
	}
	if n := h.names(); n["google.com"] != "0.0.0.0" || n["www.google.com"] != "" {
		t.Errorf("hosts = %v", n)
	}
	if _, err := a.RemoveAllowRule("mail.google.com"); err != nil {
		t.Fatal(err)
	}
	if !a.proxy.HostBlocked("mail.google.com") {
		t.Error("allow removal not applied")
	}
}

func TestQAAppSafeSearchSync(t *testing.T) {
	a, h := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	if _, err := a.AddBlockRule("google.com", false); err != nil {
		t.Fatal(err)
	}
	if err := a.SetSafeSearch("", true); err != nil {
		t.Fatal(err)
	}
	n := h.names()
	if n["google.com"] != "0.0.0.0" || n["www.google.com"] != "216.239.38.120" {
		t.Errorf("SafeSearch on: %v", n)
	}
	if err := a.SetSafeSearch("wrong", false); err == nil {
		t.Error("SafeSearch turned off with a wrong password")
	}
	if err := a.SetSafeSearch(testPassword, false); err != nil {
		t.Fatal(err)
	}
	if n := h.names(); !reflect.DeepEqual(n, map[string]string{"localhost": "127.0.0.1", "google.com": "0.0.0.0"}) {
		t.Errorf("SafeSearch off: %v", n)
	}
}

func TestQAAppReadOnlyConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"blockRules":[`), 0600); err != nil {
		t.Fatal(err)
	}
	a, _ := newTestApp(t, p)
	v, err := a.AddBlockRule("google.com", false)
	if err != nil || v.Apply.ConfigError != i18n.T("err.settingsReadOnly") {
		t.Fatalf("read-only add: %+v %v", v, err)
	}
	if !a.proxy.HostBlocked("google.com") {
		t.Error("in-memory rule must still be enforced")
	}
	if _, err := a.RemoveBlockRule("", "google.com"); err == nil {
		t.Error("remove must fail closed without a readable password")
	}
	if data, _ := os.ReadFile(p); string(data) != `{"blockRules":[` {
		t.Error("corrupt file modified")
	}
}

func TestDisableClearsHostsAndOffIsReported(t *testing.T) {
	a, h := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	if _, err := a.AddBlockRule("google.com", false); err != nil {
		t.Fatal(err)
	}
	if !a.GetStatus().Layer1Active {
		t.Fatal("layer 1 must be active after a block rule was written")
	}
	if err := a.DisableProtection(testPassword); err != nil {
		t.Fatal(err)
	}
	if h.active() || h.names()["google.com"] != "" {
		t.Fatalf("hosts not cleared on disable: %q", h.content)
	}
	if a.GetStatus().Layer1Active {
		t.Fatal("layer 1 must be off after disable")
	}
	calls := h.calls
	v, err := a.AddBlockRule("google.co.il", false)
	if err != nil || h.calls != calls || v.Apply.HostsApplied || v.Apply.HostsInfo != i18n.T("info.hostsProtectionOff") {
		t.Fatalf("change while off: %+v %v", v.Apply, err)
	}
	if !a.proxy.HostBlocked("google.co.il") {
		t.Error("proxy policy must still follow the rules")
	}
}

func TestDisableReportsClearFailure(t *testing.T) {
	a, h := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	a.AddBlockRule("google.com", false)
	h.err = hosts.ErrElevationCancelled
	err := a.DisableProtection(testPassword)
	if err == nil || !strings.Contains(err.Error(), i18n.T("err.hostsElevationDeclined")) {
		t.Fatalf("clear failure must be reported: %v", err)
	}
	if a.GetStatus().Diagnostics.LastApply.HostsError == "" {
		t.Error("the failed clear must stay visible in diagnostics")
	}
}

func TestHostsDeclineIsWarningNotFailure(t *testing.T) {
	a, h := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	a.AddBlockRule("google.com", false)
	h.err = hosts.ErrElevationCancelled
	if _, err := a.AddBlockRule("google.co.il", false); err != nil {
		t.Fatal(err)
	}
	calls := h.calls
	if err := a.AddKeyword("kw"); err != nil {
		t.Fatalf("a keyword change must not fail on hosts: %v", err)
	}
	if err := a.StartFocusMode(5); err != nil {
		t.Fatalf("focus mode must not fail on hosts: %v", err)
	}
	if h.calls != calls {
		t.Fatalf("declined plan prompted again %d times", h.calls-calls)
	}
	if got := a.GetStatus().Diagnostics.LastApply.HostsError; got != i18n.T("err.hostsElevationDeclined") {
		t.Fatalf("hosts warning = %q", got)
	}
	h.err = nil
	if v := a.RetryHosts(); v.HostsError != "" || h.names()["google.co.il"] != "0.0.0.0" {
		t.Fatalf("retry: %+v", v)
	}
}

func TestEnableProtectionPromptsAgain(t *testing.T) {
	a, h := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	h.err = hosts.ErrElevationCancelled
	a.AddBlockRule("google.com", false)
	calls := h.calls
	a.applier.Apply()
	if h.calls != calls {
		t.Fatal("unchanged declined plan prompted again")
	}
	h.err = nil
	if err := a.EnableProtection(); err != nil { // already running: only re-applies
		t.Fatal(err)
	}
	if h.calls != calls+1 || h.names()["google.com"] != "0.0.0.0" {
		t.Fatalf("EnableProtection must retry hosts: calls %d", h.calls-calls)
	}
}

func TestBuiltinExemptRuleNotice(t *testing.T) {
	a, h := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	v, err := a.AddBlockRule("accounts.google.com", false)
	if err != nil || v.Notice != i18n.T("notice.ruleBuiltinExempt", "accounts.google.com") {
		t.Fatalf("notice = %q %v", v.Notice, err)
	}
	if _, ok := h.names()["accounts.google.com"]; ok {
		t.Fatal("built-in service written to hosts")
	}
	if v, _ := a.AddBlockRule("google.com", false); v.Notice != "" {
		t.Fatalf("unexpected notice %q", v.Notice)
	}
}

func TestRulesDisplayIDN(t *testing.T) {
	a, _ := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	v, err := a.AddBlockRule("\u05d3\u05d5\u05d2\u05de\u05d4.com", false)
	if err != nil {
		t.Fatal(err)
	}
	d := v.Block[0].Domain
	if !strings.HasPrefix(d, "xn--") || v.Display[d] != "\u05d3\u05d5\u05d2\u05de\u05d4.com" {
		t.Fatalf("domain %q display %v", d, v.Display)
	}
	if _, err := a.RemoveBlockRule(testPassword, d); err != nil {
		t.Fatal("the punycode domain stays the key: ", err)
	}
}

func TestCorruptConfigLeavesHostsAndReloads(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"blockRules":[`), 0600); err != nil {
		t.Fatal(err)
	}
	a, h := newTestApp(t, p)
	h.content = "127.0.0.1 localhost\r\n# K10-Web-Protection START\r\n0.0.0.0 google.com\r\n# K10-Web-Protection END\r\n"
	before := h.content
	if st := a.applier.Enforce(); st.HostsApplied || h.content != before {
		t.Fatalf("startup enforce touched hosts: %+v %q", st, h.content)
	}
	if !a.GetStatus().Layer1Active {
		t.Error("the untouched hosts section is still active")
	}
	if _, err := a.ReloadSettings(); err == nil {
		t.Fatal("reload of a still corrupt file must fail")
	}
	if !a.conf().ReadOnly() {
		t.Fatal("failed reload must keep the fail-closed config")
	}
	if err := os.WriteFile(p, []byte(`{"settingsVersion":3,"blockRules":[{"domain":"google.co.il"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := a.ReloadSettings()
	if err != nil || d.ReadOnly || d.LoadError != "" {
		t.Fatalf("reload: %+v %v", d, err)
	}
	if !a.proxy.HostBlocked("google.co.il") || h.names()["google.co.il"] != "0.0.0.0" || h.names()["google.com"] == "0.0.0.0" {
		t.Fatalf("reloaded rules not enforced: %q", h.content)
	}
	if _, err := a.AddBlockRule("google.com", false); err != nil || !strings.Contains(readFile(t, p), "google.com") {
		t.Fatal("reloaded config must save again")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestUninstallHostsCleanup(t *testing.T) {
	ps, err := exec.LookPath("powershell")
	if err != nil {
		t.Skip("powershell not available")
	}
	sec := func(m, body string) string { return "# " + m + " START\r\n" + body + "# " + m + " END\r\n" }
	in := "\ufeff" + sec("K10-Web-Protection", "0.0.0.0 a.com\r\n") +
		"127.0.0.1 localhost\r\n# caf\xe9 foreign\r\n" +
		sec("K9-Web-Protection", "0.0.0.0 b.com\r\n") +
		"10.0.0.1 x # K10-SafeSearch START\r\n" +
		sec("K10-SafeSearch", "216.239.38.120 www.google.com\r\n") +
		"::1 localhost"
	want := "\ufeff127.0.0.1 localhost\r\n# caf\xe9 foreign\r\n10.0.0.1 x # K10-SafeSearch START\r\n::1 localhost"
	p := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(p, []byte(in), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", "$hostsPath = $env:K10_HOSTS\n"+hostsCleanupPS)
	cmd.Env = append(os.Environ(), "K10_HOSTS="+p)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if got := readFile(t, p); got != want {
		t.Fatalf("hosts after cleanup = %q", got)
	}
}

func TestEmptyHostsPlanIsIdleNotInactive(t *testing.T) {
	a, h := newTestApp(t, filepath.Join(t.TempDir(), "config.json"))
	if err := a.EnableProtection(); err != nil {
		t.Fatal(err)
	}
	s := a.GetStatus()
	if !s.ProxyRunning || s.Layer1Active || !s.Layer1Idle || h.active() {
		t.Fatalf("empty plan: running %v layer1 %v idle %v", s.ProxyRunning, s.Layer1Active, s.Layer1Idle)
	}
	a.AddBlockRule("google.com", false)
	if s := a.GetStatus(); !s.Layer1Active || s.Layer1Idle {
		t.Fatalf("written plan: layer1 %v idle %v", s.Layer1Active, s.Layer1Idle)
	}
	h.err = hosts.ErrElevationCancelled
	a.RemoveBlockRule(testPassword, "google.com")
	h.content = "127.0.0.1 localhost\r\n"
	if s := a.GetStatus(); s.Layer1Active || s.Layer1Idle {
		t.Fatalf("failed apply must not count as idle: layer1 %v idle %v", s.Layer1Active, s.Layer1Idle)
	}
	atomic.StoreInt32(&a.proxyRunning, 0)
	if s := a.GetStatus(); s.Layer1Idle {
		t.Fatal("idle only while protection is on")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func listening(port int) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err == nil {
		c.Close()
	}
	return err == nil
}

func TestReloadKeepsRunningPort(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"blockRules":[`), 0600); err != nil {
		t.Fatal(err)
	}
	a, _ := newTestApp(t, p)
	oldPort, newPort := freePort(t), freePort(t)
	a.conf().Update(func(c *config.Config) { c.ProxyPort = oldPort })
	atomic.StoreInt32(&a.proxyRunning, 0)
	if err := a.startProxyAndWait(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.proxy.Stop)
	body := fmt.Sprintf(`{"settingsVersion":3,"proxyPort":%d}`, newPort)
	if err := os.WriteFile(p, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReloadSettings(); err != nil {
		t.Fatal(err)
	}
	if a.listenPort() != oldPort || a.GetStatus().ProxyPort != oldPort || !listening(oldPort) {
		t.Fatalf("running port moved: listen %d status %d", a.listenPort(), a.GetStatus().ProxyPort)
	}
	a.proxy.Stop()
	atomic.StoreInt32(&a.proxyRunning, 0)
	if err := a.startProxyAndWait(); err != nil {
		t.Fatal(err)
	}
	if a.listenPort() != newPort || !listening(newPort) {
		t.Fatalf("restart must use the reloaded port: %d", a.listenPort())
	}
}

func TestConcurrentReloadSwapsConsistently(t *testing.T) {
	for i := 0; i < 20; i++ {
		p := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(p, []byte(`{"blockRules":[`), 0600); err != nil {
			t.Fatal(err)
		}
		a, _ := newTestApp(t, p)
		if err := os.WriteFile(p, []byte(`{"settingsVersion":3}`), 0600); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for j := 0; j < 4; j++ {
			wg.Add(1)
			go func() { defer wg.Done(); a.ReloadSettings() }()
		}
		wg.Wait()
		if _, err := a.AddBlockRule("google.com", false); err != nil {
			t.Fatal(err)
		}
		if !a.proxy.HostBlocked("google.com") {
			t.Fatal("applier enforces a different config than the app edits")
		}
	}
}
