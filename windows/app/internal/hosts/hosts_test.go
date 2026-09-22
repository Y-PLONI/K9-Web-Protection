package hosts

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func exact(hs ...string) []Rule {
	var rs []Rule
	for _, h := range hs {
		rs = append(rs, Rule{Host: h})
	}
	return rs
}

func mappedNames(s string) map[string][]string {
	m := map[string][]string{}
	for _, l := range strings.Split(s, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && !strings.HasPrefix(f[0], "#") {
			m[f[1]] = append(m[f[1]], f[0])
		}
	}
	return m
}

func TestRender(t *testing.T) {
	foreignCRLF := "# Copyright\r\n\r\n127.0.0.1 localhost\r\n  10.0.0.5   intranet.local  # office\r\n"
	tests := []struct {
		name    string
		current string
		plan    Plan
		want    string
		check   func(t *testing.T, out string, res Result)
	}{
		{
			name:    "foreign CRLF lines preserved, section appended",
			current: foreignCRLF,
			plan:    Plan{Block: exact("example.com")},
			want:    foreignCRLF + markerStart + "\r\n0.0.0.0 example.com\r\n" + markerEnd + "\r\n",
		},
		{
			name:    "LF style kept",
			current: "127.0.0.1 localhost\n",
			plan:    Plan{Block: exact("example.com")},
			want:    "127.0.0.1 localhost\n" + markerStart + "\n0.0.0.0 example.com\n" + markerEnd + "\n",
		},
		{
			name:    "BOM kept and missing final newline added",
			current: bom + "127.0.0.1 localhost",
			plan:    Plan{Block: exact("example.com")},
			want:    bom + "127.0.0.1 localhost\r\n" + markerStart + "\r\n0.0.0.0 example.com\r\n" + markerEnd + "\r\n",
		},
		{
			name: "legacy K9 and old K10 sections removed, new one in first position",
			current: "a\r\n# K9-Web-Protection START\r\n0.0.0.0 old.com\r\n# K9-Web-Protection END\r\nb\r\n" +
				"# K10-SafeSearch START\r\n216.239.38.120 google.com\r\n# K10-SafeSearch END\r\nc\r\n",
			plan: Plan{Block: exact("new.com")},
			want: "a\r\n" + markerStart + "\r\n0.0.0.0 new.com\r\n" + markerEnd + "\r\nb\r\nc\r\n",
		},
		{
			name:    "empty plan removes managed section",
			current: "a\r\n" + markerStart + "\r\n0.0.0.0 x.com\r\n" + markerEnd + "\r\nb\r\n",
			plan:    Plan{},
			want:    "a\r\nb\r\n",
		},
		{
			name:    "dangling START does not eat the rest of the file",
			current: "a\r\n" + markerStart + "\r\n0.0.0.0 x.com\r\nb\r\n127.0.0.1 keep.local\r\n",
			plan:    Plan{Block: exact("y.com")},
			want: "a\r\n" + markerStart + "\r\n0.0.0.0 x.com\r\nb\r\n127.0.0.1 keep.local\r\n" +
				markerStart + "\r\n0.0.0.0 y.com\r\n" + markerEnd + "\r\n",
		},
		{
			name:    "dangling legacy START before a real section is kept",
			current: "# K9-Web-Protection START\r\nfoo\r\n" + markerStart + "\r\n0.0.0.0 x.com\r\n" + markerEnd + "\r\n",
			plan:    Plan{},
			want:    "# K9-Web-Protection START\r\nfoo\r\n",
		},
		{
			name:    "stray END is foreign",
			current: markerEnd + "\r\nfoo\r\n",
			plan:    Plan{},
			want:    markerEnd + "\r\nfoo\r\n",
		},
		{
			name:    "exact rules emit only those names",
			current: "",
			plan:    Plan{Block: exact("google.com", "www.google.com", "google.co.il", "www.google.co.il")},
			check: func(t *testing.T, out string, res Result) {
				want := []string{"google.co.il", "google.com", "www.google.co.il", "www.google.com"}
				if !reflect.DeepEqual(res.BlockedNames, want) {
					t.Fatalf("names = %v", res.BlockedNames)
				}
				if len(mappedNames(out)) != 4 || strings.Contains(out, "mail.google.com") || res.Partial {
					t.Fatalf("unexpected output %q partial=%v", out, res.Partial)
				}
			},
		},
		{
			name:    "include subdomains adds www and marks partial",
			current: "",
			plan:    Plan{Block: []Rule{{Host: "Example.COM.", IncludeSubdomains: true}, {Host: "www.b.com", IncludeSubdomains: true}}},
			check: func(t *testing.T, out string, res Result) {
				want := []string{"example.com", "www.b.com", "www.example.com"}
				if !reflect.DeepEqual(res.BlockedNames, want) || !res.Partial {
					t.Fatalf("names = %v partial=%v", res.BlockedNames, res.Partial)
				}
			},
		},
		{
			name:    "allow precedence exact and subdomain aware",
			current: "",
			plan: Plan{
				Block: []Rule{{Host: "a.com", IncludeSubdomains: true}, {Host: "b.com", IncludeSubdomains: true}, {Host: "c.com"}},
				Allow: []Rule{{Host: "www.a.com"}, {Host: "b.com", IncludeSubdomains: true}, {Host: "www.c.com"}},
			},
			check: func(t *testing.T, out string, res Result) {
				if !reflect.DeepEqual(res.BlockedNames, []string{"a.com", "c.com"}) {
					t.Fatalf("names = %v", res.BlockedNames)
				}
			},
		},
		{
			name:    "invalid hosts are skipped",
			current: "",
			plan:    Plan{Block: exact("", "1.2.3.4", "bad host.com", "x.com\r\n0.0.0.0 y.com", "ok.com")},
			check: func(t *testing.T, out string, res Result) {
				if !reflect.DeepEqual(res.BlockedNames, []string{"ok.com"}) {
					t.Fatalf("names = %v", res.BlockedNames)
				}
			},
		},
		{
			name:    "SafeSearch on",
			current: "",
			plan:    Plan{SafeSearch: true},
			check: func(t *testing.T, out string, res Result) {
				m := mappedNames(out)
				if len(res.SafeSearchNames) != len(safeSearchEntries) || m["google.com"][0] != "216.239.38.120" {
					t.Fatalf("unexpected %q", out)
				}
			},
		},
		{
			name:    "SafeSearch skips blocked names",
			current: "",
			plan:    Plan{SafeSearch: true, Block: exact("google.com")},
			check: func(t *testing.T, out string, res Result) {
				m := mappedNames(out)
				if !reflect.DeepEqual(m["google.com"], []string{"0.0.0.0"}) {
					t.Fatalf("google.com mapped to %v", m["google.com"])
				}
				if !reflect.DeepEqual(m["www.google.com"], []string{"216.239.38.120"}) {
					t.Fatalf("www.google.com mapped to %v", m["www.google.com"])
				}
				for _, n := range res.SafeSearchNames {
					if n == "google.com" {
						t.Fatal("google.com listed as SafeSearch name")
					}
				}
			},
		},
		{
			name:    "SafeSearch off and nothing blocked leaves file alone",
			current: foreignCRLF,
			plan:    Plan{},
			want:    foreignCRLF,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, res := Render(tc.current, tc.plan)
			if tc.check == nil && out != tc.want {
				t.Fatalf("got  %q\nwant %q", out, tc.want)
			}
			if tc.check != nil {
				tc.check(t, out, res)
			}
			if res.Changed != (out != tc.current) {
				t.Fatalf("Changed = %v", res.Changed)
			}
			again, res2 := Render(out, tc.plan)
			if again != out || res2.Changed {
				t.Fatalf("not idempotent:\n%q\n%q", out, again)
			}
		})
	}
}

func withTempHosts(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	oldPath, oldElev, oldFlush := pathFn, elevate, flushDNS
	pathFn = func() string { return p }
	elevate = func(string, string) error { t.Fatal("unexpected elevation"); return nil }
	flushDNS = func() {}
	t.Cleanup(func() {
		os.Chmod(p, 0644)
		pathFn, elevate, flushDNS = oldPath, oldElev, oldFlush
	})
	return p
}

func TestApply(t *testing.T) {
	p := withTempHosts(t, "127.0.0.1 localhost\r\n")
	plan := Plan{Block: exact("example.com")}

	res, err := Apply(plan)
	if err != nil || !res.Changed || res.Path != p {
		t.Fatalf("first apply: %+v %v", res, err)
	}
	if !IsActive() {
		t.Fatal("IsActive = false after apply")
	}
	st, _ := os.Stat(p)
	res, err = Apply(plan)
	if err != nil || res.Changed {
		t.Fatalf("second apply: %+v %v", res, err)
	}
	if st2, _ := os.Stat(p); !st2.ModTime().Equal(st.ModTime()) {
		t.Fatal("file rewritten on no-op apply")
	}
	if err := Clear(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(p); string(data) != "127.0.0.1 localhost\r\n" || IsActive() {
		t.Fatalf("after Clear: %q", data)
	}
}

func TestApplyReadOnly(t *testing.T) {
	p := withTempHosts(t, "127.0.0.1 localhost\r\n")
	if err := os.Chmod(p, 0444); err != nil {
		t.Fatal(err)
	}
	if os.WriteFile(p, []byte("x"), 0644) == nil {
		t.Skip("read-only file is writable here")
	}

	elevate = func(string, string) error { return ErrElevationCancelled }
	if _, err := Apply(Plan{Block: exact("example.com")}); !errors.Is(err, ErrElevationCancelled) {
		t.Fatalf("err = %v", err)
	}

	elevate = func(string, string) error { return nil } // claims success but writes nothing
	if _, err := Apply(Plan{Block: exact("example.com")}); !errors.Is(err, ErrVerifyFailed) {
		t.Fatalf("err = %v", err)
	}
	if data, _ := os.ReadFile(p); string(data) != "127.0.0.1 localhost\r\n" {
		t.Fatalf("file modified: %q", data)
	}
}
