package hosts

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	exitCancelled   = 1223 // ERROR_CANCELLED from the UAC prompt
	exitWriteFailed = 2
	elevateTimeout  = 5 * time.Minute
)

func psQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

func tempFile(pattern, content string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	_, werr := f.WriteString(content)
	cerr := f.Close()
	if werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(f.Name())
		return "", werr
	}
	return f.Name(), nil
}

// scriptFile writes a .ps1 with a UTF-8 BOM; without it PowerShell 5.1 reads non-ASCII paths as ANSI.
func scriptFile(content string) (string, error) {
	return tempFile("k10hosts-*.ps1", bom+content)
}

func innerScript(dst, src, errLog string) string {
	return "$ErrorActionPreference = 'Stop'\r\n" +
		"try {\r\n" +
		"  $dst = " + psQuote(dst) + "\r\n" +
		"  $item = Get-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue\r\n" +
		"  $ro = $item -and $item.IsReadOnly\r\n" +
		"  if ($ro) { $item.IsReadOnly = $false }\r\n" +
		"  [System.IO.File]::WriteAllBytes($dst, [System.IO.File]::ReadAllBytes(" + psQuote(src) + "))\r\n" +
		"  if ($ro) { (Get-Item -LiteralPath $dst -Force).IsReadOnly = $true }\r\n" +
		"  exit 0\r\n" +
		"} catch {\r\n" +
		"  Set-Content -LiteralPath " + psQuote(errLog) + " -Value $_.Exception.Message\r\n" +
		"  exit " + fmt.Sprint(exitWriteFailed) + "\r\n" +
		"}\r\n"
}

func launcherScript(script string) string {
	args := `-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "` + script + `"`
	return "$ErrorActionPreference = 'Stop'\r\n" +
		"try {\r\n" +
		"  $p = Start-Process powershell -ArgumentList " + psQuote(args) + " -Verb RunAs -WindowStyle Hidden -Wait -PassThru\r\n" +
		"  exit $p.ExitCode\r\n" +
		"} catch {\r\n" +
		"  $e = $_.Exception\r\n" +
		"  while ($e) { if ($e -is [System.ComponentModel.Win32Exception] -and $e.NativeErrorCode -eq " + fmt.Sprint(exitCancelled) + ") { exit " + fmt.Sprint(exitCancelled) + " }; $e = $e.InnerException }\r\n" +
		"  [Console]::Error.WriteLine($_.Exception.Message)\r\n" +
		"  exit 1\r\n" +
		"}\r\n"
}

// writeWithElevation copies content over dst from an elevated PowerShell and checks its exit code.
func writeWithElevation(dst, content string) error {
	src, err := tempFile("k10hosts-*.txt", content)
	if err != nil {
		return fmt.Errorf("could not write temp hosts file: %w", err)
	}
	defer os.Remove(src)
	errLog, err := tempFile("k10hosts-*.err", "")
	if err != nil {
		return fmt.Errorf("could not create temp log file: %w", err)
	}
	defer os.Remove(errLog)

	script, err := scriptFile(innerScript(dst, src, errLog))
	if err != nil {
		return fmt.Errorf("could not write script file: %w", err)
	}
	defer os.Remove(script)

	ctx, cancel := context.WithTimeout(context.Background(), elevateTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", launcherScript(script))
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return nil
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return fmt.Errorf("could not start elevated write: %w", err)
	}
	switch ee.ExitCode() {
	case exitCancelled:
		return ErrElevationCancelled
	case exitWriteFailed:
		msg, _ := os.ReadFile(errLog)
		return fmt.Errorf("elevated write failed: %s", strings.TrimSpace(string(msg)))
	default:
		return fmt.Errorf("elevated write failed (exit %d): %s", ee.ExitCode(), strings.TrimSpace(string(out)))
	}
}

func flushDNSCache() {
	cmd := exec.Command("ipconfig", "/flushdns")
	hideWindow(cmd)
	_ = cmd.Run()
}
