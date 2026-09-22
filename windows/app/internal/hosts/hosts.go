package hosts

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

const (
	markerStart = "# K10-Web-Protection START"
	markerEnd   = "# K10-Web-Protection END"

	blockIP = "0.0.0.0"
	bom     = "\ufeff"
)

// Every managed section kind; only markerStart/markerEnd is ever written.
var sectionMarkers = [][2]string{
	{markerStart, markerEnd},
	{"# K10-SafeSearch START", "# K10-SafeSearch END"},
	{"# K9-Web-Protection START", "# K9-Web-Protection END"},
}

// SafeSearch enforcement IPs published by Google / Microsoft for parental controls.
var safeSearchEntries = [][2]string{
	// Google — forcesafesearch.google.com
	{"216.239.38.120", "www.google.com"},
	{"216.239.38.120", "google.com"},
	// YouTube Restricted
	{"216.239.38.119", "www.youtube.com"},
	{"216.239.38.119", "m.youtube.com"},
	{"216.239.38.119", "youtubei.googleapis.com"},
	{"216.239.38.119", "youtube.googleapis.com"},
	{"216.239.38.119", "www.youtube-nocookie.com"},
	// Bing — strict.bing.com
	{"204.79.197.220", "www.bing.com"},
	{"204.79.197.220", "bing.com"},
}

var (
	ErrElevationCancelled = errors.New("hosts: administrator permission was declined")
	ErrVerifyFailed       = errors.New("hosts: file content does not match after write")
)

type Rule struct {
	Host              string
	IncludeSubdomains bool
}

type Plan struct {
	Block, Allow []Rule
	SafeSearch   bool
}

type Result struct {
	Changed         bool
	BlockedNames    []string
	SafeSearchNames []string
	Path            string
	Partial         bool // some include-subdomain rules can't be fully enforced by hosts
}

var (
	mu       sync.Mutex
	pathFn   = hostsPath
	elevate  = writeWithElevation
	flushDNS = flushDNSCache
)

// hostsPath returns the Windows hosts file path, respecting %SystemRoot%.
func hostsPath() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, `System32\drivers\etc\hosts`)
}

func cleanHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
	if h == "" || net.ParseIP(h) != nil {
		return ""
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return ""
		}
	}
	return h
}

func ruleMatches(r Rule, name string) bool {
	h := cleanHost(r.Host)
	if h == "" {
		return false
	}
	return name == h || (r.IncludeSubdomains && strings.HasSuffix(name, "."+h))
}

func allowed(allow []Rule, name string) bool {
	for _, r := range allow {
		if ruleMatches(r, name) {
			return true
		}
	}
	return false
}

func lineMarker(line string) string {
	return strings.TrimSpace(line)
}

func startKind(line string) int {
	m := lineMarker(line)
	for k, p := range sectionMarkers {
		if m == p[0] {
			return k
		}
	}
	return -1
}

// sectionEnd returns the END index for a START at i, or -1 if it is dangling.
func sectionEnd(lines []string, i int) int {
	end := sectionMarkers[startKind(lines[i])][1]
	for j := i + 1; j < len(lines); j++ {
		if lineMarker(lines[j]) == end {
			return j
		}
		if startKind(lines[j]) >= 0 {
			return -1
		}
	}
	return -1
}

func splitLines(body string) []string {
	lines := strings.SplitAfter(body, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// Render returns current with its managed sections replaced by one built from plan.
func Render(current string, plan Plan) (string, Result) {
	var res Result
	hasBOM := strings.HasPrefix(current, bom)
	body := strings.TrimPrefix(current, bom)
	eol := "\r\n"
	if !strings.Contains(body, "\r\n") && strings.Contains(body, "\n") {
		eol = "\n"
	}

	lines := splitLines(body)
	out := make([]string, 0, len(lines))
	insertAt := -1
	for i := 0; i < len(lines); i++ {
		if startKind(lines[i]) >= 0 {
			if j := sectionEnd(lines, i); j >= 0 {
				if insertAt < 0 {
					insertAt = len(out)
				}
				i = j
				continue
			}
		}
		out = append(out, lines[i])
	}

	blocked := map[string]bool{}
	add := func(name string) {
		if name != "" && !blocked[name] && !allowed(plan.Allow, name) {
			blocked[name] = true
			res.BlockedNames = append(res.BlockedNames, name)
		}
	}
	for _, r := range plan.Block {
		h := cleanHost(r.Host)
		if h == "" {
			continue
		}
		add(h)
		if r.IncludeSubdomains {
			res.Partial = true
			if !strings.HasPrefix(h, "www.") {
				add("www." + h)
			}
		}
	}
	sort.Strings(res.BlockedNames)

	var section []string
	for _, n := range res.BlockedNames {
		section = append(section, blockIP+" "+n+eol)
	}
	if plan.SafeSearch {
		for _, e := range safeSearchEntries {
			if blocked[e[1]] {
				continue
			}
			section = append(section, e[0]+" "+e[1]+eol)
			res.SafeSearchNames = append(res.SafeSearchNames, e[1])
		}
	}

	if len(section) > 0 {
		if insertAt < 0 {
			insertAt = len(out)
		}
		if insertAt > 0 && !strings.HasSuffix(out[insertAt-1], "\n") {
			out[insertAt-1] += eol
		}
		section = append([]string{markerStart + eol}, section...)
		section = append(section, markerEnd+eol)
		out = append(out[:insertAt], append(section, out[insertAt:]...)...)
	}

	next := strings.Join(out, "")
	if hasBOM {
		next = bom + next
	}
	res.Changed = next != current
	return next, res
}

// Apply renders plan into the hosts file, writing (elevated if needed) only on change.
func Apply(plan Plan) (Result, error) {
	mu.Lock()
	defer mu.Unlock()

	path := pathFn()
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Result{Path: path}, fmt.Errorf("hosts: read %s: %w", path, err)
	}
	next, res := Render(string(data), plan)
	res.Path = path
	if !res.Changed {
		return res, nil
	}

	if derr := os.WriteFile(path, []byte(next), 0644); derr != nil {
		if eerr := elevate(path, next); eerr != nil {
			return res, fmt.Errorf("hosts: write %s: %w (direct write: %v)", path, eerr, derr)
		}
	}

	got, err := os.ReadFile(path)
	if err != nil {
		return res, fmt.Errorf("%w: %s: %v", ErrVerifyFailed, path, err)
	}
	if string(got) != next {
		return res, fmt.Errorf("%w: %s", ErrVerifyFailed, path)
	}
	flushDNS()
	return res, nil
}

// Clear removes all managed sections from the hosts file.
func Clear() error {
	_, err := Apply(Plan{})
	return err
}

// IsActive reports whether a well-formed K10 section is present.
func IsActive() bool {
	data, err := os.ReadFile(pathFn())
	if err != nil {
		return false
	}
	lines := splitLines(strings.TrimPrefix(string(data), bom))
	for i, l := range lines {
		if lineMarker(l) == markerStart && sectionEnd(lines, i) >= 0 {
			return true
		}
	}
	return false
}
