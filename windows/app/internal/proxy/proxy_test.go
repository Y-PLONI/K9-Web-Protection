package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "k10-proxy-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	SetCADir(dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestCanonicalHost(t *testing.T) {
	cases := map[string]string{
		"Google.COM":         "google.com",
		"google.com:443":     "google.com",
		"google.com.":        "google.com",
		"WWW.Google.com.:80": "www.google.com",
		"  mail.google.com ": "mail.google.com",
		"[::1]:443":          "::1",
		"[2001:DB8::1]":      "2001:db8::1",
		"::1":                "::1",
		"127.0.0.1:8080":     "127.0.0.1",
		"":                   "",
	}
	for in, want := range cases {
		if got := CanonicalHost(in); got != want {
			t.Errorf("CanonicalHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchRule(t *testing.T) {
	exact := Rule{Host: "google.com"}
	subs := Rule{Host: "google.com", IncludeSubdomains: true}
	cases := []struct {
		host string
		r    Rule
		want bool
	}{
		{"google.com", exact, true},
		{"GOOGLE.com:443", exact, true},
		{"google.com.", exact, true},
		{"www.google.com", exact, false},
		{"mail.google.com", exact, false},
		{"google.com", subs, true},
		{"www.google.com", subs, true},
		{"a.b.google.com", subs, true},
		{"notgoogle.com", subs, false},
		{"google.com.evil.org", subs, false},
		{"google.co.il", subs, false},
		{"google.com", Rule{Host: "Google.Com."}, true},
		{"google.com", Rule{}, false},
		{"", subs, false},
	}
	for _, c := range cases {
		if got := MatchRule(c.host, c.r); got != c.want {
			t.Errorf("MatchRule(%q, %+v) = %v, want %v", c.host, c.r, got, c.want)
		}
	}
}

func basePolicy() Policy { return Policy{FilterLevel: LevelMonitor} }

func TestExactRulesLeaveSubdomainsAlone(t *testing.T) {
	p := New(0, nil)
	pol := basePolicy()
	for _, h := range []string{"google.com", "www.google.com", "google.co.il", "www.google.co.il"} {
		pol.Block = append(pol.Block, Rule{Host: h})
	}
	p.SetPolicy(pol)
	for _, h := range []string{"google.com", "www.google.com", "google.co.il", "www.google.co.il", "WWW.GOOGLE.COM:443"} {
		if !p.HostBlocked(h) {
			t.Errorf("%s should be blocked", h)
		}
	}
	for _, h := range []string{"mail.google.com", "accounts.google.com", "drive.google.com", "calendar.google.com"} {
		if p.HostBlocked(h) {
			t.Errorf("%s should be allowed", h)
		}
	}
}

func TestAllowTakesPrecedence(t *testing.T) {
	p := New(0, nil)
	pol := basePolicy()
	pol.Block = []Rule{{Host: "google.com", IncludeSubdomains: true}}
	pol.Allow = []Rule{{Host: "mail.google.com"}}
	p.SetPolicy(pol)
	want := map[string]bool{
		"google.com":        true,
		"drive.google.com":  true,
		"x.mail.google.com": true,
		"mail.google.com":   false,
		"example.org":       false,
	}
	for h, blocked := range want {
		if got := p.HostBlocked(h); got != blocked {
			t.Errorf("HostBlocked(%s) = %v, want %v", h, got, blocked)
		}
	}
}

func TestFocusAndKeywords(t *testing.T) {
	p := New(0, nil)
	pol := basePolicy()
	pol.Focus = func(h string) bool { return h == "news.example" }
	pol.Keywords = []string{"", "Forbidden"}
	p.SetPolicy(pol)
	if !p.HostBlocked("news.example") {
		t.Error("focus host should be blocked")
	}
	if !p.HostBlocked("forbiddenthing.example") {
		t.Error("keyword host should be blocked")
	}
	if p.HostBlocked("other.example") {
		t.Error("empty keyword must not match everything")
	}
}

func TestPolicyReturnsApplied(t *testing.T) {
	p := New(0, nil)
	if got := p.Policy(); len(got.Block) != 0 || got.SafeSearch {
		t.Fatalf("initial policy not empty: %+v", got)
	}
	in := Policy{
		Block:        []Rule{{Host: "Google.COM.", IncludeSubdomains: true}, {Host: ""}},
		Allow:        []Rule{{Host: "mail.google.com"}},
		FilterLevel:  LevelHigh,
		BlockYouTube: true,
		SafeSearch:   true,
		Keywords:     []string{"abc"},
		Focus:        func(string) bool { return false },
	}
	p.SetPolicy(in)
	in.Keywords[0] = "mutated"
	got := p.Policy()
	if len(got.Block) != 1 || got.Block[0] != (Rule{Host: "google.com", IncludeSubdomains: true}) {
		t.Errorf("Block = %+v", got.Block)
	}
	if len(got.Allow) != 1 || got.Allow[0].Host != "mail.google.com" {
		t.Errorf("Allow = %+v", got.Allow)
	}
	if got.FilterLevel != LevelHigh || !got.BlockYouTube || !got.SafeSearch || got.Focus == nil {
		t.Errorf("scalar fields not applied: %+v", got)
	}
	if len(got.Keywords) != 1 || got.Keywords[0] != "abc" {
		t.Errorf("Keywords = %v", got.Keywords)
	}
	got.Block[0].Host = "changed"
	if p.Policy().Block[0].Host != "google.com" {
		t.Error("Policy() must return a copy")
	}
}

// ── Live proxy helpers ────────────────────────────────────────────────────────

type dialLog struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialLog) add(a string) {
	d.mu.Lock()
	d.addrs = append(d.addrs, a)
	d.mu.Unlock()
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

// startProxy runs a proxy whose upstream dials all go to target.
func startProxy(t *testing.T, target string, pol Policy) (*Proxy, string, *dialLog) {
	t.Helper()
	log := &dialLog{}
	p := New(0, nil)
	p.Dial = func(network, addr string) (net.Conn, error) {
		log.add(addr)
		return net.Dial(network, target)
	}
	p.SetPolicy(pol)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- p.Serve(l) }()
	t.Cleanup(func() {
		p.Stop()
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Serve returned %v", err)
		}
	})
	return p, l.Addr().String(), log
}

type tunnelConn struct {
	net.Conn
	br *bufio.Reader
}

func connect(t *testing.T, proxyAddr, target string) *tunnelConn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT %s: %v", target, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT %s: status %d", target, resp.StatusCode)
	}
	return &tunnelConn{Conn: c, br: br}
}

func (tc *tunnelConn) echo(msg string) error {
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	defer tc.SetDeadline(time.Time{})
	if _, err := io.WriteString(tc, msg); err != nil {
		return err
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(tc.br, buf); err != nil {
		return err
	}
	if string(buf) != msg {
		return fmt.Errorf("echo got %q", buf)
	}
	return nil
}

// closedByProxy reports whether the proxy closed the connection (EOF/reset, not a timeout).
func (tc *tunnelConn) closedByProxy() bool {
	tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := tc.br.ReadByte()
	var ne net.Error
	return err != nil && !(errors.As(err, &ne) && ne.Timeout())
}

func kinds(p *Proxy) map[string]string {
	out := map[string]string{}
	for _, ti := range p.ActiveTunnels() {
		out[ti.Host] = ti.Kind
	}
	return out
}

// ── Live proxy tests ──────────────────────────────────────────────────────────

func TestSetPolicyClosesOnlyNewlyBlockedTunnels(t *testing.T) {
	p, addr, _ := startProxy(t, echoServer(t), basePolicy())
	root := connect(t, addr, "google.com:443")
	mail := connect(t, addr, "mail.google.com:443")
	for _, tc := range []*tunnelConn{root, mail} {
		if err := tc.echo("hello"); err != nil {
			t.Fatal(err)
		}
	}
	if got := kinds(p); got["google.com"] != KindRaw || got["mail.google.com"] != KindRaw {
		t.Fatalf("ActiveTunnels = %v", got)
	}

	pol := basePolicy()
	pol.Block = []Rule{{Host: "google.com"}}
	if n := p.SetPolicy(pol); n != 1 {
		t.Errorf("SetPolicy closed %d tunnels, want 1", n)
	}
	if !root.closedByProxy() {
		t.Error("tunnel to blocked host still open")
	}
	if err := mail.echo("still flowing"); err != nil {
		t.Errorf("mail.google.com tunnel broken: %v", err)
	}
	if got := kinds(p); len(got) != 1 || got["mail.google.com"] != KindRaw {
		t.Errorf("ActiveTunnels after SetPolicy = %v", got)
	}
	if n := p.Reevaluate(); n != 0 {
		t.Errorf("second Reevaluate closed %d", n)
	}
}

func TestSubdomainBlockWithExactAllow(t *testing.T) {
	p, addr, _ := startProxy(t, echoServer(t), basePolicy())
	drive := connect(t, addr, "drive.google.com:443")
	mail := connect(t, addr, "mail.google.com:443")

	pol := basePolicy()
	pol.Block = []Rule{{Host: "google.com", IncludeSubdomains: true}}
	pol.Allow = []Rule{{Host: "mail.google.com"}}
	if n := p.SetPolicy(pol); n != 1 {
		t.Errorf("closed %d, want 1", n)
	}
	if !drive.closedByProxy() {
		t.Error("drive.google.com tunnel still open")
	}
	if err := mail.echo("ping"); err != nil {
		t.Errorf("allowed tunnel broken: %v", err)
	}
}

func TestModeChangeClosesTunnels(t *testing.T) {
	p, addr, _ := startProxy(t, echoServer(t), basePolicy())
	raw := connect(t, addr, "www.bing.com:443")
	if err := raw.echo("x"); err != nil {
		t.Fatal(err)
	}
	pol := basePolicy()
	pol.SafeSearch = true
	if n := p.SetPolicy(pol); n != 1 {
		t.Errorf("enabling SafeSearch closed %d, want 1", n)
	}
	if !raw.closedByProxy() {
		t.Error("raw tunnel survived switch to SafeSearch MITM")
	}

	mitm := connect(t, addr, "www.google.com:443")
	if got := kinds(p)["www.google.com"]; got != KindSafeSearch {
		t.Fatalf("kind = %q, want %q", got, KindSafeSearch)
	}
	pol.SafeSearch = false
	if n := p.SetPolicy(pol); n != 1 {
		t.Errorf("disabling SafeSearch closed %d, want 1", n)
	}
	if !mitm.closedByProxy() {
		t.Error("MITM tunnel survived switch to raw")
	}
}

func TestStopClosesHijackedTunnels(t *testing.T) {
	p, addr, _ := startProxy(t, echoServer(t), basePolicy())
	tc := connect(t, addr, "example.org:443")
	if err := tc.echo("x"); err != nil {
		t.Fatal(err)
	}
	p.Stop()
	if !tc.closedByProxy() {
		t.Error("tunnel still open after Stop")
	}
	if n := len(p.ActiveTunnels()); n != 0 {
		t.Errorf("%d tunnels tracked after Stop", n)
	}
}

func TestHTTPForwardAndBlock(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "origin:"+r.Host)
	}))
	defer origin.Close()
	pol := basePolicy()
	pol.Block = []Rule{{Host: "blocked.example"}}
	_, addr, log := startProxy(t, origin.Listener.Addr().String(), pol)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: addr})}}
	resp, err := client.Get("http://open.example/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "origin:open.example" {
		t.Errorf("forward: %d %q", resp.StatusCode, body)
	}

	resp, err = client.Get("http://blocked.example/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("blocked host status %d", resp.StatusCode)
	}
	log.mu.Lock()
	for _, a := range log.addrs {
		if strings.HasPrefix(a, "blocked.example") {
			t.Errorf("proxy dialed blocked host %s", a)
		}
	}
	log.mu.Unlock()
}

func TestConcurrentPolicySwaps(t *testing.T) {
	p, addr, _ := startProxy(t, echoServer(t), basePolicy())
	tc := connect(t, addr, "mail.google.com:443")
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				pol := basePolicy()
				pol.Block = []Rule{{Host: fmt.Sprintf("h%d-%d.example", i, j)}}
				p.SetPolicy(pol)
			}
		}(i)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				p.HostBlocked("mail.google.com")
				p.ActiveTunnels()
				p.Policy()
			}
		}()
	}
	wg.Wait()
	if err := tc.echo("after"); err != nil {
		t.Errorf("unaffected tunnel broken: %v", err)
	}
}
