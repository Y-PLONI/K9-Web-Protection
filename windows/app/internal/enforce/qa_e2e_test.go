package enforce

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"k10webprotection/internal/config"
	"k10webprotection/internal/hosts"
	"k10webprotection/internal/proxy"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "k10-enforce-test")
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

var candidates = []string{
	"google.com", "www.google.com", "google.co.il", "www.google.co.il",
	"mail.google.com", "accounts.google.com", "drive.google.com", "calendar.google.com",
	"www.mail.google.com", "google.co.uk", "images.google.co.il",
}

func loadTemp(t *testing.T) (*config.Config, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	c, err := config.LoadWith(config.LoadOptions{Path: p, LegacyPaths: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return c, p
}

func configBlocks(v config.PolicyView, host string) bool {
	for _, r := range v.Allow {
		if r.Matches(host) {
			return false
		}
	}
	for _, r := range v.Block {
		if r.Matches(host) {
			return true
		}
	}
	return false
}

func sorted(m map[string]bool) []string {
	var out []string
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// layers returns the hosts each layer blocks among candidates.
func layers(t *testing.T, c *config.Config) (cfg, px, hf []string) {
	t.Helper()
	v := c.PolicyView()
	p := proxy.New(0, nil)
	p.SetPolicy(PolicyFor(v, nil))
	cm, pm := map[string]bool{}, map[string]bool{}
	for _, h := range candidates {
		cm[h] = configBlocks(v, h)
		pm[h] = p.HostBlocked(h)
	}
	_, res := hosts.Render("", PlanFor(v))
	return sorted(cm), sorted(pm), res.BlockedNames
}

func TestQALayersAgreeOnExactRules(t *testing.T) {
	c, _ := loadTemp(t)
	for _, in := range []string{"http://GOOGLE.com/", "WWW.Google.com.", "google.co.il", "https://www.google.co.il/"} {
		r, err := config.ParseRule(in, false)
		if err != nil {
			t.Fatal(err)
		}
		c.UpsertBlockRule(r)
	}
	want := []string{"google.co.il", "google.com", "www.google.co.il", "www.google.com"}
	cfg, px, hf := layers(t, c)
	for name, got := range map[string][]string{"config": cfg, "proxy": px, "hosts": hf} {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s blocks %v, want %v", name, got, want)
		}
	}
}

func TestQALayersAgreeOnSubdomainsWithAllow(t *testing.T) {
	c, _ := loadTemp(t)
	c.UpsertBlockRule(config.DomainRule{Domain: "google.com", IncludeSubdomains: true})
	c.UpsertAllowRule(config.DomainRule{Domain: "mail.google.com"})
	cfg, px, hf := layers(t, c)
	want := []string{"accounts.google.com", "calendar.google.com", "drive.google.com", "google.com", "www.google.com", "www.mail.google.com"}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("config %v, want %v", cfg, want)
	}
	// the proxy never blocks its built-in critical services (accounts.google.com)
	if want := append([]string{}, want[1:]...); !reflect.DeepEqual(px, want) {
		t.Fatalf("proxy %v, want %v", px, want)
	}
	// hosts is best effort: only the apex and www, never an allowed name
	if !reflect.DeepEqual(hf, []string{"google.com", "www.google.com"}) {
		t.Fatalf("hosts %v", hf)
	}
}

func TestQAAllowBeatsBlockInAllLayers(t *testing.T) {
	c, _ := loadTemp(t)
	c.UpsertBlockRule(config.DomainRule{Domain: "google.com"})
	c.UpsertBlockRule(config.DomainRule{Domain: "google.co.il", IncludeSubdomains: true})
	c.UpsertAllowRule(config.DomainRule{Domain: "google.com"})
	c.UpsertAllowRule(config.DomainRule{Domain: "google.co.il", IncludeSubdomains: true})
	cfg, px, hf := layers(t, c)
	if len(cfg) != 0 || len(px) != 0 || len(hf) != 0 {
		t.Fatalf("config %v proxy %v hosts %v, want nothing", cfg, px, hf)
	}
}

// ── in-process end to end ────────────────────────────────────────────────────

type dials struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dials) add(a string) { d.mu.Lock(); d.addrs = append(d.addrs, a); d.mu.Unlock() }

func (d *dials) count(prefix string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, a := range d.addrs {
		if strings.HasPrefix(a, prefix) {
			n++
		}
	}
	return n
}

func echoServer(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return l.Addr().String()
}

type tconn struct {
	net.Conn
	br *bufio.Reader
}

func connect(t *testing.T, addr, target string) *tconn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: %v %v", target, resp, err)
	}
	return &tconn{Conn: c, br: br}
}

func (c *tconn) echo(msg string) error {
	c.SetDeadline(time.Now().Add(3 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := io.WriteString(c, msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo got %q", buf)
	}
	return nil
}

func (c *tconn) closed() bool {
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := c.br.ReadByte()
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func tunnelKinds(p *proxy.Proxy) map[string]string {
	out := map[string]string{}
	for _, ti := range p.ActiveTunnels() {
		out[ti.Host] = ti.Kind
	}
	return out
}

// fileHosts applies plans to a temp hosts file the same way hosts.Apply does, minus elevation.
func fileHosts(t *testing.T) (HostsFunc, string) {
	p := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(p, []byte("127.0.0.1 localhost\r\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return func(plan hosts.Plan) (hosts.Result, error) {
		cur, err := os.ReadFile(p)
		if err != nil {
			return hosts.Result{}, err
		}
		next, res := hosts.Render(string(cur), plan)
		res.Path = p
		if res.Changed {
			err = os.WriteFile(p, []byte(next), 0644)
		}
		return res, err
	}, p
}

func hostsMap(t *testing.T, p string) map[string]string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, l := range strings.Split(string(data), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && !strings.HasPrefix(f[0], "#") {
			m[f[1]] = f[0]
		}
	}
	return m
}

func TestQAEndToEnd(t *testing.T) {
	c, cfgPath := loadTemp(t)
	c.Update(func(c *config.Config) { c.SafeSearch = false })

	echo := echoServer(t)
	dl := &dials{}
	px := proxy.New(0, nil)
	px.Dial = func(network, addr string) (net.Conn, error) {
		dl.add(addr)
		return net.Dial(network, echo)
	}
	hf, hostsPath := fileHosts(t)
	a := New(c, px, hf, func() bool { return true })
	if st := a.Enforce(); st.Err() != nil {
		t.Fatal(st.Err())
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- px.Serve(l) }()
	t.Cleanup(func() {
		px.Stop()
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve: %v", err)
		}
	})
	addr := l.Addr().String()

	root := connect(t, addr, "google.com:443")
	mail := connect(t, addr, "mail.google.com:443")
	for _, tc := range []*tconn{root, mail} {
		if err := tc.echo("before"); err != nil {
			t.Fatal(err)
		}
	}

	for _, in := range []string{"http://GOOGLE.com/", "www.google.com", "google.co.il", "www.google.co.il"} {
		r, err := config.ParseRule(in, false)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.UpsertBlockRule(r); err != nil {
			t.Fatal(err)
		}
	}
	st := a.Apply()
	if st.Err() != nil || st.ClosedTunnels != 1 || !st.HostsApplied || st.Hosts.Partial {
		t.Fatalf("apply: %+v", st)
	}
	if !root.closed() {
		t.Error("open google.com tunnel not closed")
	}
	if err := mail.echo("after"); err != nil {
		t.Errorf("mail.google.com tunnel broken: %v", err)
	}

	before := dl.count("google.com:")
	connect(t, addr, "google.com:443")
	if k := tunnelKinds(px)["google.com"]; k != proxy.KindBlock {
		t.Errorf("new google.com CONNECT kind %q", k)
	}
	if dl.count("google.com:") != before {
		t.Error("blocked host was dialed")
	}
	for _, h := range []string{"mail.google.com", "accounts.google.com", "drive.google.com", "calendar.google.com"} {
		if err := connect(t, addr, h+":443").echo("x"); err != nil {
			t.Errorf("%s: %v", h, err)
		}
	}

	wantHosts := map[string]string{
		"localhost": "127.0.0.1", "google.com": "0.0.0.0", "www.google.com": "0.0.0.0",
		"google.co.il": "0.0.0.0", "www.google.co.il": "0.0.0.0",
	}
	if got := hostsMap(t, hostsPath); !reflect.DeepEqual(got, wantHosts) {
		t.Errorf("hosts = %v", got)
	}

	c2, err := config.LoadWith(config.LoadOptions{Path: cfgPath, LegacyPaths: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	wantRules := []config.DomainRule{{Domain: "google.com"}, {Domain: "www.google.com"}, {Domain: "google.co.il"}, {Domain: "www.google.co.il"}}
	if got := c2.GetBlockRules(); !reflect.DeepEqual(got, wantRules) {
		t.Errorf("saved rules = %+v", got)
	}

	// SafeSearch on: blocked names keep 0.0.0.0, off: SafeSearch lines go, blocks stay
	c.Update(func(c *config.Config) { c.SafeSearch = true })
	if st := a.Apply(); st.Err() != nil {
		t.Fatal(st.Err())
	}
	m := hostsMap(t, hostsPath)
	if m["google.com"] != "0.0.0.0" || m["www.google.com"] != "0.0.0.0" || m["www.bing.com"] != "204.79.197.220" {
		t.Errorf("SafeSearch on: %v", m)
	}
	c.Update(func(c *config.Config) { c.SafeSearch = false })
	a.Apply()
	if got := hostsMap(t, hostsPath); !reflect.DeepEqual(got, wantHosts) {
		t.Errorf("SafeSearch off: %v", got)
	}

	// removing a rule reopens the host
	if !c.RemoveBlockRule("GOOGLE.COM") {
		t.Fatal("remove failed")
	}
	a.Apply()
	if err := connect(t, addr, "google.com:443").echo("open again"); err != nil {
		t.Errorf("google.com after remove: %v", err)
	}
	if _, ok := hostsMap(t, hostsPath)["google.com"]; ok {
		t.Error("google.com still in hosts after remove")
	}
}

func TestQASaveFailureStillEnforces(t *testing.T) {
	c, cfgPath := loadTemp(t)
	if err := os.Mkdir(cfgPath, 0700); err != nil {
		t.Fatal(err)
	}
	px := proxy.New(0, nil)
	hf, hostsPath := fileHosts(t)
	a := New(c, px, hf, func() bool { return true })
	c.UpsertBlockRule(config.DomainRule{Domain: "google.com"})
	st := a.Apply()
	if st.ConfigErr == nil || st.HostsErr != nil {
		t.Fatalf("want config error only: %+v", st)
	}
	if !px.HostBlocked("google.com") || px.HostBlocked("mail.google.com") {
		t.Error("proxy must enforce the in-memory rules")
	}
	if hostsMap(t, hostsPath)["google.com"] != "0.0.0.0" {
		t.Error("hosts must enforce the in-memory rules")
	}
}

func TestQAProtectionOffLeavesHostsAlone(t *testing.T) {
	c, _ := loadTemp(t)
	px := proxy.New(0, nil)
	hf, hostsPath := fileHosts(t)
	a := New(c, px, hf, func() bool { return false })
	c.UpsertBlockRule(config.DomainRule{Domain: "google.com"})
	if st := a.Apply(); st.Err() != nil || st.HostsApplied {
		t.Fatalf("%+v", st)
	}
	if got := hostsMap(t, hostsPath); len(got) != 1 {
		t.Errorf("hosts touched while off: %v", got)
	}
	if !px.HostBlocked("google.com") {
		t.Error("proxy policy must still update")
	}
}

func TestQABuiltinAllowedNotWrittenToHosts(t *testing.T) {
	c, _ := loadTemp(t)
	c.UpsertBlockRule(config.DomainRule{Domain: "accounts.google.com"})
	_, px, hf := layers(t, c)
	if len(px) != 0 {
		t.Fatalf("proxy blocks %v", px)
	}
	if len(hf) != 0 {
		t.Fatalf("hosts blocks %v, which the proxy exempts as a built-in critical service", hf)
	}
}

func TestCorruptConfigKeepsHostsBlocks(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(`{"blockRules":[`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := config.LoadWith(config.LoadOptions{Path: p, LegacyPaths: []string{}})
	if err == nil || !c.LoadFailed() {
		t.Fatalf("want a load failure: %v", err)
	}
	hf, hostsPath := fileHosts(t)
	if _, err := hf(hosts.Plan{Block: []hosts.Rule{{Host: "google.com"}}}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(hostsPath)
	st := New(c, proxy.New(0, nil), hf, func() bool { return true }).Enforce()
	if after, _ := os.ReadFile(hostsPath); string(after) != string(before) || !errors.Is(st.HostsSkipped, ErrSettingsUnreadable) {
		t.Fatalf("hosts changed on a corrupt config: %q %+v", after, st)
	}
}
