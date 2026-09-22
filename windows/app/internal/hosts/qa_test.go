package hosts

import (
	"os"
	"reflect"
	"testing"
)

func TestQASafeSearchOffKeepsBlocks(t *testing.T) {
	p := withTempHosts(t, "127.0.0.1 localhost\r\n")
	block := exact("google.com", "www.google.co.il")

	if _, err := Apply(Plan{Block: block, SafeSearch: true}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	m := mappedNames(string(data))
	if !reflect.DeepEqual(m["google.com"], []string{"0.0.0.0"}) || !reflect.DeepEqual(m["www.google.com"], []string{"216.239.38.120"}) {
		t.Fatalf("SafeSearch on: %q", data)
	}

	res, err := Apply(Plan{Block: block, SafeSearch: false})
	if err != nil || !res.Changed || len(res.SafeSearchNames) != 0 {
		t.Fatalf("SafeSearch off: %+v %v", res, err)
	}
	data, _ = os.ReadFile(p)
	m = mappedNames(string(data))
	want := map[string][]string{
		"localhost":        {"127.0.0.1"},
		"google.com":       {"0.0.0.0"},
		"www.google.co.il": {"0.0.0.0"},
	}
	if !reflect.DeepEqual(m, want) {
		t.Fatalf("after SafeSearch off: %v", m)
	}
	if !IsActive() {
		t.Fatal("section must remain while blocks exist")
	}
}

func TestQASafeSearchSkipsSubdomainBlockedNames(t *testing.T) {
	out, res := Render("", Plan{SafeSearch: true, Block: []Rule{{Host: "google.com", IncludeSubdomains: true}}})
	m := mappedNames(out)
	for _, n := range []string{"google.com", "www.google.com"} {
		if !reflect.DeepEqual(m[n], []string{"0.0.0.0"}) {
			t.Errorf("%s mapped to %v", n, m[n])
		}
	}
	for _, n := range res.SafeSearchNames {
		if n == "google.com" || n == "www.google.com" {
			t.Errorf("%s listed as SafeSearch name", n)
		}
	}
	if !reflect.DeepEqual(m["www.bing.com"], []string{"204.79.197.220"}) {
		t.Errorf("other SafeSearch names must stay: %v", m["www.bing.com"])
	}
}

func TestQAExactWwwBlockLeavesApexSafeSearch(t *testing.T) {
	out, _ := Render("", Plan{SafeSearch: true, Block: exact("www.google.com")})
	m := mappedNames(out)
	if !reflect.DeepEqual(m["www.google.com"], []string{"0.0.0.0"}) || !reflect.DeepEqual(m["google.com"], []string{"216.239.38.120"}) {
		t.Fatalf("got %v", m)
	}
}

func TestQAAllowedNameNotBlocked(t *testing.T) {
	out, res := Render("", Plan{
		Block: []Rule{{Host: "google.com", IncludeSubdomains: true}},
		Allow: []Rule{{Host: "www.google.com"}},
	})
	if !reflect.DeepEqual(res.BlockedNames, []string{"google.com"}) {
		t.Fatalf("names = %v", res.BlockedNames)
	}
	if _, ok := mappedNames(out)["www.google.com"]; ok {
		t.Fatalf("allowed name written: %q", out)
	}
}
