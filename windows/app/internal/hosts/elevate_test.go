package hosts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func powershell(t *testing.T) string {
	p, err := exec.LookPath("powershell")
	if err != nil {
		t.Skip("powershell not available")
	}
	return p
}

func TestElevationScriptsParse(t *testing.T) {
	ps := powershell(t)
	dir := t.TempDir()
	for name, script := range map[string]string{
		"inner":    innerScript(`C:\it's\hosts`, filepath.Join(dir, "src"), filepath.Join(dir, "err")),
		"launcher": launcherScript(filepath.Join(dir, "s.ps1")),
	} {
		check := "$e = $null; [void][System.Management.Automation.Language.Parser]::ParseInput($env:K10_SCRIPT, [ref]$null, [ref]$e); if ($e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }"
		cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", check)
		cmd.Env = append(os.Environ(), "K10_SCRIPT="+script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s script does not parse: %v %s", name, err, out)
		}
	}
}

// Runs the inner script unelevated against a temp file to check the write logic.
func TestInnerScriptWrites(t *testing.T) {
	ps := powershell(t)
	dir := t.TempDir()
	dst, src, errLog, script := filepath.Join(dir, "hosts"), filepath.Join(dir, "src"), filepath.Join(dir, "err"), filepath.Join(dir, "s.ps1")
	want := "\ufeff127.0.0.1 localhost\r\n"
	os.WriteFile(dst, []byte("old\n"), 0644)
	os.Chmod(dst, 0444)
	defer os.Chmod(dst, 0644)
	os.WriteFile(src, []byte(want), 0644)
	os.WriteFile(script, []byte(innerScript(dst, src, errLog)), 0644)

	out, err := exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script).CombinedOutput()
	if err != nil {
		msg, _ := os.ReadFile(errLog)
		t.Fatalf("inner script failed: %v %s %s", err, out, msg)
	}
	if got, _ := os.ReadFile(dst); string(got) != want {
		t.Fatalf("dst = %q", got)
	}
	if st, _ := os.Stat(dst); st.Mode().Perm()&0200 != 0 {
		t.Fatal("read-only attribute not restored")
	}

	os.Remove(src)
	err = exec.Command(ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script).Run()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != exitWriteFailed {
		t.Fatalf("missing source: err = %v", err)
	}
	if msg, _ := os.ReadFile(errLog); strings.TrimSpace(string(msg)) == "" {
		t.Fatal("no error message logged")
	}
}

func TestScriptFileHasBOMAndKeepsHebrewPath(t *testing.T) {
	ps := powershell(t)
	dir := filepath.Join(t.TempDir(), "משתמש")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "src")
	script, err := scriptFile(innerScript(filepath.Join(dir, "hosts"), src, filepath.Join(dir, "err")))
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(script)
	data, _ := os.ReadFile(script)
	if !strings.HasPrefix(string(data), "\xEF\xBB\xBF") {
		t.Fatalf("script has no UTF-8 BOM: % x", data[:3])
	}
	// Windows PowerShell 5.1 must parse the file and see the Hebrew path unchanged.
	check := "$e = $null; $ast = [System.Management.Automation.Language.Parser]::ParseFile($env:K10_FILE, [ref]$null, [ref]$e); " +
		"if ($e.Count) { $e | ForEach-Object { $_.Message }; exit 1 }; if (-not $ast.Extent.Text.Contains($env:K10_WANT)) { exit 3 }"
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", check)
	cmd.Env = append(os.Environ(), "K10_FILE="+script, "K10_WANT="+src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("script with a Hebrew path does not round-trip: %v %s", err, out)
	}
}
