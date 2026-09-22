package proxy

import (
	"context"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"k10webprotection/internal/database"
	"k10webprotection/internal/i18n"
)

const blockPageTpl = `<!DOCTYPE html>
<html lang="%[1]s" dir="%[2]s">
<head>
<meta charset="utf-8">
<title>%[3]s</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%%;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Helvetica Neue',Arial,sans-serif;background:#d4d0c8;display:flex;align-items:center;justify-content:center;padding:20px}
.frame{background:#fff;border:1px solid #888;box-shadow:2px 2px 10px rgba(0,0,0,.25);max-width:520px;width:100%%;overflow:hidden}
.hdr{background:linear-gradient(180deg,#1a5ca8 0%%,#144985 60%%,#0d3260 100%%);padding:12px 18px;display:flex;align-items:center;gap:12px}
.hdr-logo{width:40px;height:40px;background:rgba(255,255,255,.15);border-radius:50%%;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.hdr-title{font-size:16px;font-weight:800;color:#fff;letter-spacing:-.2px}
.body{padding:36px 32px 28px;text-align:center}
.icon-wrap{margin:0 auto 18px}
.chip{display:inline-block;background:#fde8e8;color:#8b0000;font-size:10px;font-weight:800;letter-spacing:1.5px;text-transform:uppercase;padding:3px 12px;border-radius:2px;margin-bottom:14px;border:1px solid #f0c0c0}
h1{font-size:20px;font-weight:800;color:#144985;margin-bottom:14px}
.domain-row{display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:18px}
.domain-label{font-size:11px;font-weight:700;color:#555;text-transform:uppercase;letter-spacing:.8px}
.domain-val{background:#f0f4fa;border:1px solid #aab8cc;padding:5px 14px;font-size:14px;font-weight:700;color:#cc3333;max-width:340px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.msg{font-size:12px;color:#555;line-height:1.7;max-width:400px;margin:0 auto 22px}
.chips-row{display:flex;gap:8px;justify-content:center;flex-wrap:wrap}
.info-chip{background:#f4f7fb;border:1px solid #b0bdd0;padding:4px 12px;font-size:11px;color:#144985;font-weight:600;border-radius:2px}
.ftr-bar{background:linear-gradient(180deg,#1a5ca8 0%%,#0d3260 100%%);padding:8px 18px;display:flex;justify-content:flex-end;align-items:center}
.brand{font-size:14px;font-weight:900;color:#fff;letter-spacing:.3px}
.brand-star{color:#f0a500;margin:0 3px}
.brand-ver{font-size:9px;font-weight:600;color:#8bb8e8;margin-left:2px;vertical-align:super}
.ftr-copy{background:#e4e0d8;text-align:center;padding:4px 8px;font-size:9px;color:#777;border-top:1px solid #ccc}
</style>
</head>
<body>
<div class="frame">
  <div class="hdr">
    <div class="hdr-logo">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(240,165,0,.35)" stroke="#f0a500" stroke-width="1.8"/>
        <polyline points="9 12 11 14 15 10" stroke="white" stroke-width="2.2"/>
      </svg>
    </div>
    <div class="hdr-title">%[4]s</div>
  </div>
  <div class="body">
    <div class="icon-wrap">
      <svg width="76" height="76" viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="#fde8e8" stroke="#cc3333" stroke-width="1.4"/>
        <line x1="15" y1="9" x2="9" y2="15" stroke="#cc3333" stroke-width="2.2"/>
        <line x1="9" y1="9" x2="15" y2="15" stroke="#cc3333" stroke-width="2.2"/>
      </svg>
    </div>
    <div class="chip">%[5]s</div>
    <h1>%[6]s</h1>
    <div class="domain-row">
      <span class="domain-label">%[7]s</span>
      <div class="domain-val">%[8]s</div>
    </div>
    <p class="msg">%[9]s</p>
    <div class="chips-row">
      <div class="info-chip">%[10]s</div>
      <div class="info-chip">%[11]s</div>
    </div>
  </div>
  <div class="ftr-bar">
    <div class="brand">K10<span class="brand-star">&#9733;</span>WebProtection<span class="brand-ver">PRO</span></div>
  </div>
  <div class="ftr-copy">%[12]s</div>
</div>
</body>
</html>`

func blockPageHTML(domain string) string {
	// Argument order must match the %[n]s indexes used in blockPageTpl.
	return fmt.Sprintf(blockPageTpl,
		i18n.Lang(),                  // 1  <html lang>
		i18n.Dir(),                   // 2  <html dir>
		i18n.T("block.pageTitle"),    // 3
		i18n.T("block.headerTitle"),  // 4
		i18n.T("block.chip"),         // 5
		i18n.T("block.heading"),      // 6
		i18n.T("block.siteLabel"),    // 7
		html.EscapeString(domain),    // 8
		i18n.T("block.message"),      // 9
		i18n.T("block.chipFiltered"), // 10
		i18n.T("block.chipContact"),  // 11
		i18n.T("block.copyright"),    // 12
	)
}

type OnBlockFn func(domain string)

// reevaluateEvery re-checks open tunnels so time-based rules (focus windows) take effect.
const reevaluateEvery = 30 * time.Second

type Proxy struct {
	// Dial opens upstream connections; nil uses net.DialTimeout. Set before Start.
	Dial func(network, addr string) (net.Conn, error)

	db      *database.Database
	onBlock OnBlockFn
	policy  atomic.Pointer[Policy]

	mu     sync.Mutex
	port   int
	server *http.Server
	stop   chan struct{}

	tmu     sync.Mutex
	running bool
	tunnels map[*tunnel]struct{}

	transportOnce sync.Once
	transport     http.RoundTripper
}

func New(port int, onBlock OnBlockFn) *Proxy {
	initMITM()
	p := &Proxy{port: port, db: database.DB, onBlock: onBlock, tunnels: map[*tunnel]struct{}{}}
	p.policy.Store(&Policy{})
	return p
}

// SetPort takes effect on the next Start.
func (p *Proxy) SetPort(port int) {
	p.mu.Lock()
	p.port = port
	p.mu.Unlock()
}

func (p *Proxy) Start() error {
	p.mu.Lock()
	port := p.port
	p.mu.Unlock()
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	return p.Serve(l)
}

func (p *Proxy) Serve(l net.Listener) error {
	srv := &http.Server{
		Handler: http.HandlerFunc(p.handle),
		// Do NOT set ReadTimeout/WriteTimeout — they kill long-lived HTTPS tunnels.
		// Only limit the time to read the initial request headers.
		ReadHeaderTimeout: 15 * time.Second,
	}
	stop := make(chan struct{})
	p.mu.Lock()
	if p.server != nil {
		p.mu.Unlock()
		l.Close()
		return errors.New("proxy: already running")
	}
	p.server, p.stop = srv, stop
	p.mu.Unlock()

	p.tmu.Lock()
	p.running = true
	p.tmu.Unlock()
	go p.reevaluateLoop(stop)

	err := srv.Serve(l)
	if !errors.Is(err, http.ErrServerClosed) {
		p.mu.Lock()
		mine := p.server == srv
		p.mu.Unlock()
		if mine {
			p.Stop()
		}
	}
	return err
}

// Stop shuts the server down and closes every hijacked connection.
func (p *Proxy) Stop() {
	p.mu.Lock()
	srv, stop := p.server, p.stop
	p.server, p.stop = nil, nil
	p.mu.Unlock()

	p.tmu.Lock()
	p.running = false
	p.tmu.Unlock()
	p.closeTunnels()
	if srv == nil {
		return
	}
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
	p.closeTunnels() // handlers that hijacked during Shutdown
}

func (p *Proxy) reevaluateLoop(stop <-chan struct{}) {
	t := time.NewTicker(reevaluateEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			p.Reevaluate()
		}
	}
}

// SetPolicy atomically swaps the policy and closes tunnels it no longer permits.
func (p *Proxy) SetPolicy(pol Policy) (closed int) {
	c := clonePolicy(pol)
	p.policy.Store(&c)
	return p.Reevaluate()
}

func (p *Proxy) Policy() Policy {
	return clonePolicy(*p.policy.Load())
}

func (p *Proxy) HostBlocked(host string) bool {
	h := CanonicalHost(host)
	return p.decide(p.policy.Load(), h, connectRequest(net.JoinHostPort(h, "443"))) == verdictBlock
}

func (p *Proxy) dial(addr string) (net.Conn, error) {
	if p.Dial != nil {
		return p.Dial("tcp", addr)
	}
	return net.DialTimeout("tcp", addr, 10*time.Second)
}

func (p *Proxy) httpTransport() http.RoundTripper {
	if p.Dial == nil {
		return nil
	}
	p.transportOnce.Do(func() {
		p.transport = &http.Transport{DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return p.Dial(network, addr)
		}}
	})
	return p.transport
}

// ── Request handler ───────────────────────────────────────────────────────────

type verdict int

const (
	verdictPass verdict = iota
	verdictBlock
	verdictSafeSearch
)

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {
	// Recover from any panic so one bad request can't crash the proxy
	defer func() {
		if rec := recover(); rec != nil {
			http.Error(w, "Internal proxy error", http.StatusInternalServerError)
		}
	}()

	host := CanonicalHost(r.Host)
	pol := p.policy.Load()
	switch p.decide(pol, host, r) {
	case verdictBlock:
		p.block(w, r, host, pol)
	case verdictSafeSearch:
		p.safeSearchIntercept(w, r, host, pol)
	default:
		p.passThrough(w, r, host, pol)
	}
}

// decide only reads r (method and URL), so it can re-run for an open tunnel.
func (p *Proxy) decide(pol *Policy, host string, r *http.Request) verdict {
	// Built-in critical services (OS updates, safe-browsing, OCSP) — never block
	if IsBuiltinAllowed(host) {
		return verdictPass
	}

	// User allow-list wins
	if pol.allows(host) {
		return verdictPass
	}

	// User's custom block list
	if pol.blocks(host) {
		return verdictBlock
	}

	// ── Bypass prevention (always active) ────────────────────────────────────

	rawURL := r.URL.String()

	if isWebProxy(host, rawURL) {
		return verdictBlock
	}

	// Detect base64-encoded redirect destinations (?__cpo=, ?url=, etc.).
	// Catches e.g. azureserv.com/?__cpo=aHR0cHM6Ly93d3cueG54eC5jb20 → xnxx.com.
	if decodedHost := DecodeRedirectHost(rawURL); decodedHost != "" {
		if !IsBuiltinAllowed(decodedHost) && !pol.allows(decodedHost) {
			if p.db.BlocksDomainInCategories(decodedHost, LevelCategories[pol.FilterLevel]) {
				return verdictBlock
			}
		}
	}

	// ── Focus mode — block social media sites ────────────────────────────────

	if pol.focusBlocks(host) {
		return verdictBlock
	}

	// ── Level-based filtering ─────────────────────────────────────────────────

	level := pol.FilterLevel

	if level == LevelMonitor {
		// Monitor: no blocking, pass through
	} else {
		cats := LevelCategories[level] // nil for custom/unknown → blocks nothing via DB

		// Direct-IP bypass prevention (all levels except monitor/custom)
		if level != LevelCustom && level != "" && isDirectIP(host) {
			return verdictBlock
		}

		// YouTube (high level only, or custom toggle)
		if (level == LevelHigh || (level == LevelCustom || level == "") && pol.BlockYouTube) && isYouTube(host) {
			return verdictBlock
		}

		// Image search (high level only, or custom toggle)
		if (level == LevelHigh || (level == LevelCustom || level == "") && pol.BlockImageSearch) && isImageSearch(host, rawURL) {
			return verdictBlock
		}

		// Database domain lookup (category-aware for named levels, all-category for custom)
		// Communication apps (WhatsApp, Messenger, Instagram) bypass this block;
		// user's custom block list and Focus Mode (checked above) still apply.
		if !IsCommunicationAllowed(host) && (len(cats) > 0 || level == LevelCustom || level == "") {
			dbCats := cats
			if (level == LevelCustom || level == "") && pol.BlockAdultContent {
				dbCats = nil // nil = all categories
			}
			if p.db.BlocksDomainInCategories(host, dbCats) {
				return verdictBlock
			}
			// URL-level checks (HTTP only — CONNECT is an opaque tunnel)
			if r.Method != http.MethodConnect {
				// Full-URL substring patterns (.xxx TLD, /porn/ path, ?q=porn query)
				if p.db.BlocksURLInCategories(rawURL, dbCats) {
					return verdictBlock
				}
				// Keyword wildcards checked against path+query only (host covered above)
				urlPath := r.URL.Path
				if r.URL.RawQuery != "" {
					urlPath += "?" + r.URL.RawQuery
				}
				if p.db.BlocksURLPatternInCategories(urlPath, dbCats) {
					return verdictBlock
				}
				// Page-content keyword phrases
				if p.db.BlocksKeyword(rawURL) {
					return verdictBlock
				}
			}
		}
	}

	// User keyword matching (always active).
	// For HTTPS (CONNECT) we only have the hostname; for HTTP we have the full URL.
	{
		kwTarget := rawURL
		if r.Method == http.MethodConnect {
			kwTarget = host
		}
		if pol.keywordMatch(kwTarget) {
			return verdictBlock
		}
	}

	// SafeSearch MITM
	if r.Method == http.MethodConnect && pol.SafeSearch && safeSearchDomains[host] {
		return verdictSafeSearch
	}

	return verdictPass
}

func (p *Proxy) passThrough(w http.ResponseWriter, r *http.Request, host string, pol *Policy) {
	if r.Method == http.MethodConnect {
		p.tunnel(w, r, host, pol)
	} else {
		p.forward(w, r)
	}
}

// block sends the K10 block page (or a plain 403 for CONNECT).
func (p *Proxy) block(w http.ResponseWriter, r *http.Request, domain string, pol *Policy) {
	if p.onBlock != nil {
		go p.onBlock(domain) // async so it never delays the response
	}
	if r.Method == http.MethodConnect {
		p.blockTunnel(w, r, domain, pol)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Alt-Svc", "clear") // prevent QUIC/HTTP3 upgrade for this domain
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(blockPageHTML(domain)))
}

// tunnel handles HTTPS CONNECT — raw TCP pass-through (no TLS inspection).
func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, host string, pol *Policy) {
	dest, err := p.dial(r.Host)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		dest.Close()
		http.Error(w, "Hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		dest.Close()
		return
	}
	t := p.track(pol, r, host, KindRaw, conn)
	defer p.untrack(t)
	if !t.add(dest) {
		return
	}

	// Confirm tunnel to the browser
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if n := brw.Reader.Buffered(); n > 0 {
		b, _ := brw.Reader.Peek(n)
		dest.Write(b)
	}

	// Pipe both directions — wait for BOTH to finish before closing
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(dest, conn)
		if tc, ok := dest.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(conn, dest)
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// forward proxies plain HTTP requests.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = ""
	if r.URL.Scheme == "" {
		r.URL.Scheme = "http"
	}
	if r.URL.Host == "" {
		r.URL.Host = r.Host
	}
	r.Header.Del("Proxy-Connection")

	resp, err := (&http.Client{
		Transport: p.httpTransport(),
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}).Do(r)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
