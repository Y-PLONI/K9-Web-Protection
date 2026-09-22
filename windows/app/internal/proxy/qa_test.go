package proxy

import (
	"strings"
	"testing"
)

func TestQABlockedConnectBeatsSafeSearch(t *testing.T) {
	pol := basePolicy()
	pol.SafeSearch = true
	pol.Block = []Rule{{Host: "google.com"}}
	p, addr, log := startProxy(t, echoServer(t), pol)

	connect(t, addr, "google.com:443")
	connect(t, addr, "www.google.com:443")
	got := kinds(p)
	if got["google.com"] != KindBlock || got["www.google.com"] != KindSafeSearch {
		t.Fatalf("kinds = %v", got)
	}
	log.mu.Lock()
	defer log.mu.Unlock()
	for _, a := range log.addrs {
		if strings.HasPrefix(a, "google.com:") {
			t.Errorf("proxy dialed blocked host %s", a)
		}
	}
}

func TestQABlockingSafeSearchTunnelClosesIt(t *testing.T) {
	pol := basePolicy()
	pol.SafeSearch = true
	p, addr, _ := startProxy(t, echoServer(t), pol)
	www := connect(t, addr, "www.google.com:443")
	mail := connect(t, addr, "mail.google.com:443")
	if k := kinds(p)["www.google.com"]; k != KindSafeSearch {
		t.Fatalf("kind = %q", k)
	}
	mailKind := kinds(p)["mail.google.com"]

	pol.Block = []Rule{{Host: "www.google.com"}}
	if n := p.SetPolicy(pol); n != 1 {
		t.Errorf("closed %d, want 1", n)
	}
	if !www.closedByProxy() {
		t.Error("www.google.com tunnel survived its block")
	}
	if k := kinds(p)["mail.google.com"]; k != mailKind {
		t.Errorf("mail.google.com kind %q -> %q", mailKind, k)
	}
	if mailKind == KindRaw {
		if err := mail.echo("ok"); err != nil {
			t.Errorf("mail.google.com tunnel broken: %v", err)
		}
	}
}

func TestQAAllowRemovalClosesTunnel(t *testing.T) {
	pol := basePolicy()
	pol.Block = []Rule{{Host: "google.com", IncludeSubdomains: true}}
	pol.Allow = []Rule{{Host: "mail.google.com"}}
	p, addr, _ := startProxy(t, echoServer(t), pol)
	mail := connect(t, addr, "mail.google.com:443")
	if err := mail.echo("x"); err != nil {
		t.Fatal(err)
	}
	pol.Allow = nil
	if n := p.SetPolicy(pol); n != 1 {
		t.Errorf("closed %d, want 1", n)
	}
	if !mail.closedByProxy() {
		t.Error("tunnel kept after its allow rule was removed")
	}
}
