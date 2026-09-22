package enforce

import (
	"errors"
	"reflect"
	"sync"
	"testing"

	"k10webprotection/internal/config"
	"k10webprotection/internal/hosts"
	"k10webprotection/internal/proxy"
)

type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.calls = append(r.calls, s)
	r.mu.Unlock()
}

type fakeStore struct {
	rec        *recorder
	view       config.PolicyView
	saveErr    error
	loadFailed bool
}

func (s *fakeStore) Save() error                   { s.rec.add("save"); return s.saveErr }
func (s *fakeStore) PolicyView() config.PolicyView { s.rec.add("view"); return s.view }
func (s *fakeStore) FocusBlocks(host string) bool  { return host == "focus.example" }
func (s *fakeStore) LoadFailed() bool              { return s.loadFailed }

type fakeProxy struct {
	rec    *recorder
	pols   []proxy.Policy
	closed int
}

func (p *fakeProxy) SetPolicy(pol proxy.Policy) int {
	p.rec.add("proxy")
	p.pols = append(p.pols, pol)
	return p.closed
}

type fakeHosts struct {
	rec   *recorder
	plans []hosts.Plan
	res   hosts.Result
	err   error
}

func (h *fakeHosts) Apply(plan hosts.Plan) (hosts.Result, error) {
	h.rec.add("hosts")
	h.plans = append(h.plans, plan)
	return h.res, h.err
}

func setup(enabled bool) (*recorder, *fakeStore, *fakeProxy, *fakeHosts, *Applier) {
	rec := &recorder{}
	st := &fakeStore{rec: rec, view: config.PolicyView{
		FilterLevel: "default",
		SafeSearch:  true,
		Keywords:    []string{"kw"},
		Block:       []config.DomainRule{{Domain: "example.com", IncludeSubdomains: true}, {Domain: "exact.org"}},
		Allow:       []config.DomainRule{{Domain: "ok.example.com"}},
	}}
	px := &fakeProxy{rec: rec, closed: 2}
	h := &fakeHosts{rec: rec, res: hosts.Result{Changed: true, Partial: true}}
	return rec, st, px, h, New(st, px, h, func() bool { return enabled })
}

func TestApplyOrder(t *testing.T) {
	rec, _, px, _, a := setup(true)
	st := a.Apply()
	if want := []string{"save", "view", "proxy", "hosts"}; !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("calls = %v, want %v", rec.calls, want)
	}
	if st.Err() != nil || !st.HostsApplied || st.ClosedTunnels != 2 || !st.Hosts.Partial {
		t.Fatalf("unexpected status %+v", st)
	}
	pol := px.pols[0]
	wantBlock := []proxy.Rule{{Host: "example.com", IncludeSubdomains: true}, {Host: "exact.org"}}
	if !reflect.DeepEqual(pol.Block, wantBlock) || len(pol.Allow) != 1 || !pol.SafeSearch || pol.FilterLevel != "default" {
		t.Fatalf("policy = %+v", pol)
	}
	if pol.Focus == nil || !pol.Focus("focus.example") || pol.Focus("other.example") {
		t.Fatal("focus must come from the store")
	}
	if !reflect.DeepEqual(a.Last(), st) {
		t.Fatal("Last must return the latest status")
	}
}

func TestSafeSearchAndBlocksInOneWrite(t *testing.T) {
	_, _, _, h, a := setup(true)
	a.Apply()
	if len(h.plans) != 1 {
		t.Fatalf("hosts applied %d times, want 1", len(h.plans))
	}
	p := h.plans[0]
	if !p.SafeSearch || len(p.Block) != 2 || len(p.Allow) != 1 || !p.Block[0].IncludeSubdomains || p.Block[1].IncludeSubdomains {
		t.Fatalf("plan = %+v", p)
	}
}

func TestHostsSkippedWhenDisabled(t *testing.T) {
	rec, _, _, h, a := setup(false)
	st := a.Apply()
	if len(h.plans) != 0 || st.HostsApplied || st.Err() != nil {
		t.Fatalf("hosts must not be touched while protection is off: %+v", st)
	}
	if want := []string{"save", "view", "proxy"}; !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("calls = %v", rec.calls)
	}
}

func TestEnforceDoesNotSave(t *testing.T) {
	rec, _, _, _, a := setup(true)
	a.Enforce()
	if want := []string{"view", "proxy", "hosts"}; !reflect.DeepEqual(rec.calls, want) {
		t.Fatalf("calls = %v", rec.calls)
	}
}

func TestConfigErrorReported(t *testing.T) {
	_, s, px, h, a := setup(true)
	s.saveErr = config.ErrReadOnly
	st := a.Apply()
	if !errors.Is(st.ConfigErr, config.ErrReadOnly) || !errors.Is(st.Err(), config.ErrReadOnly) {
		t.Fatalf("config error lost: %+v", st)
	}
	// the in-memory policy is still enforced
	if len(px.pols) != 1 || len(h.plans) != 1 {
		t.Fatal("enforcement layers must still run")
	}
}

func TestHostsErrorReported(t *testing.T) {
	_, _, _, h, a := setup(true)
	h.err = hosts.ErrElevationCancelled
	st := a.Apply()
	if st.ConfigErr != nil || !errors.Is(st.HostsErr, hosts.ErrElevationCancelled) || st.Err() == nil {
		t.Fatalf("hosts error lost: %+v", st)
	}
	if !errors.Is(a.Last().Err(), hosts.ErrElevationCancelled) {
		t.Fatal("Last must keep the failure")
	}
	h.err = nil
	if st := a.Retry(); st.Err() != nil {
		t.Fatalf("recovered apply still failing: %v", st.Err())
	}
}

func TestDeclinedPlanNotPromptedAgain(t *testing.T) {
	_, s, _, h, a := setup(true)
	h.err = hosts.ErrElevationCancelled
	a.Apply()
	st := a.Apply() // e.g. a keyword change: same hosts plan
	if len(h.plans) != 1 || !errors.Is(st.HostsErr, hosts.ErrElevationCancelled) || st.HostsApplied {
		t.Fatalf("unchanged plan re-prompted: %d prompts, %+v", len(h.plans), st)
	}
	s.view.Block = append(s.view.Block, config.DomainRule{Domain: "new.example"})
	a.Apply()
	if len(h.plans) != 2 {
		t.Fatalf("a changed plan must prompt again: %d prompts", len(h.plans))
	}
	a.Enforce()
	a.Retry()
	if len(h.plans) != 3 {
		t.Fatalf("Retry must prompt again: %d prompts", len(h.plans))
	}
	h.err = nil
	a.Retry()
	a.Apply()
	if len(h.plans) != 5 {
		t.Fatalf("after success every apply reaches hosts: %d", len(h.plans))
	}
}

func TestLoadFailedLeavesHostsAlone(t *testing.T) {
	rec, s, px, h, a := setup(true)
	s.loadFailed = true
	st := a.Enforce()
	if len(h.plans) != 0 || st.HostsApplied || st.Err() != nil || !errors.Is(st.HostsSkipped, ErrSettingsUnreadable) {
		t.Fatalf("hosts must be left as is for an unreadable config: %+v", st)
	}
	if len(px.pols) != 1 || !reflect.DeepEqual(rec.calls, []string{"view", "proxy"}) {
		t.Fatalf("proxy must still get the fail-closed policy: %v", rec.calls)
	}
}

func TestProtectionOffSkipReason(t *testing.T) {
	_, _, _, _, a := setup(false)
	if st := a.Apply(); !errors.Is(st.HostsSkipped, ErrProtectionOff) {
		t.Fatalf("skip reason = %v", st.HostsSkipped)
	}
}

func TestClearHosts(t *testing.T) {
	enabled := true
	rec := &recorder{}
	st := &fakeStore{rec: rec, view: config.PolicyView{Block: []config.DomainRule{{Domain: "example.com"}}}}
	h := &fakeHosts{rec: rec}
	a := New(st, &fakeProxy{rec: rec}, h, func() bool { return enabled })
	a.Apply()
	enabled = false
	h.err = errors.New("boom")
	if err := a.ClearHosts(); err == nil {
		t.Fatal("clear error lost")
	}
	if p := h.plans[len(h.plans)-1]; len(p.Block) != 0 || p.SafeSearch {
		t.Fatalf("clear plan = %+v", p)
	}
	last := a.Last()
	if last.HostsApplied || last.HostsErr == nil || !errors.Is(last.HostsSkipped, ErrProtectionOff) {
		t.Fatalf("last after clear = %+v", last)
	}
	if s := a.Apply(); s.HostsErr == nil {
		t.Fatal("the failed clear must stay visible while protection is off")
	}
	h.err = nil
	if err := a.ClearHosts(); err != nil || a.Apply().HostsErr != nil {
		t.Fatal("a successful clear resets the error")
	}
}

func TestPlanForSkipsBuiltinAllowed(t *testing.T) {
	p := PlanFor(config.PolicyView{Block: []config.DomainRule{{Domain: "accounts.google.com", IncludeSubdomains: true}, {Domain: "example.com"}}})
	if len(p.Block) != 1 || p.Block[0].Host != "example.com" {
		t.Fatalf("plan = %+v", p)
	}
}

func TestApplySerialized(t *testing.T) {
	rec, _, _, _, a := setup(true)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); a.Apply() }()
	}
	wg.Wait()
	if len(rec.calls) != 80 {
		t.Fatalf("got %d calls", len(rec.calls))
	}
	for i := 0; i < len(rec.calls); i += 4 {
		if got := rec.calls[i : i+4]; !reflect.DeepEqual(got, []string{"save", "view", "proxy", "hosts"}) {
			t.Fatalf("interleaved calls at %d: %v", i, got)
		}
	}
}
