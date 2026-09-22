package proxy

import (
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"
)

// Tunnel kinds; a tunnel is closed when its host's verdict no longer maps to its kind.
const (
	KindRaw        = "raw"
	KindSafeSearch = "safesearch"
	KindBlock      = "block"
)

type TunnelInfo struct {
	Host  string
	Kind  string
	Since time.Time
}

type tunnel struct {
	host, kind string
	req        *http.Request // CONNECT line only, for re-running decide
	since      time.Time

	mu     sync.Mutex
	conns  []net.Conn
	closed bool
}

// add registers another end of the tunnel; false (and c closed) if already closed.
func (t *tunnel) add(c net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		c.Close()
		return false
	}
	t.conns = append(t.conns, c)
	return true
}

func (t *tunnel) close() {
	t.mu.Lock()
	conns := t.conns
	t.conns, t.closed = nil, true
	t.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

func connectRequest(hostport string) *http.Request {
	return &http.Request{Method: http.MethodConnect, Host: hostport, URL: &url.URL{Host: hostport}}
}

func kindOf(v verdict) string {
	switch v {
	case verdictBlock:
		return KindBlock
	case verdictSafeSearch:
		return KindSafeSearch
	}
	return KindRaw
}

// track registers a hijacked client conn; pol is the policy the decision was made with.
func (p *Proxy) track(pol *Policy, r *http.Request, host, kind string, c net.Conn) *tunnel {
	t := &tunnel{host: host, kind: kind, req: connectRequest(r.Host), since: time.Now(), conns: []net.Conn{c}}
	p.tmu.Lock()
	running := p.running
	if running {
		p.tunnels[t] = struct{}{}
	}
	p.tmu.Unlock()
	if !running {
		t.close()
		return t
	}
	// The policy may have been swapped after decide but before registration.
	if cur := p.policy.Load(); cur != pol && kindOf(p.decide(cur, host, t.req)) != kind {
		t.close()
	}
	return t
}

func (p *Proxy) untrack(t *tunnel) {
	p.tmu.Lock()
	delete(p.tunnels, t)
	p.tmu.Unlock()
	t.close()
}

func (p *Proxy) snapshot() []*tunnel {
	p.tmu.Lock()
	defer p.tmu.Unlock()
	out := make([]*tunnel, 0, len(p.tunnels))
	for t := range p.tunnels {
		out = append(out, t)
	}
	return out
}

// Reevaluate closes tunnels that are now blocked or whose mode changed.
func (p *Proxy) Reevaluate() int {
	pol := p.policy.Load()
	kinds := map[string]string{}
	n := 0
	for _, t := range p.snapshot() {
		k, ok := kinds[t.req.Host]
		if !ok {
			k = kindOf(p.decide(pol, t.host, t.req))
			kinds[t.req.Host] = k
		}
		if k == t.kind {
			continue
		}
		p.tmu.Lock()
		delete(p.tunnels, t)
		p.tmu.Unlock()
		t.close()
		n++
	}
	return n
}

func (p *Proxy) closeTunnels() {
	p.tmu.Lock()
	all := p.tunnels
	p.tunnels = map[*tunnel]struct{}{}
	p.tmu.Unlock()
	for t := range all {
		t.close()
	}
}

func (p *Proxy) ActiveTunnels() []TunnelInfo {
	ts := p.snapshot()
	out := make([]TunnelInfo, 0, len(ts))
	for _, t := range ts {
		out = append(out, TunnelInfo{Host: t.host, Kind: t.kind, Since: t.since})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.Before(out[j].Since) })
	return out
}
