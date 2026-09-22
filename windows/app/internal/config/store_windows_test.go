//go:build windows

package config

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadRetriesSharingViolation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	writeFile(t, p, `{"settingsVersion":3,"passwordHash":"`+customHash+`"}`)
	name, _ := syscall.UTF16PtrFromString(p)
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, 0, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		syscall.CloseHandle(h)
	}()
	c, err := LoadWith(LoadOptions{Path: p, LegacyPaths: []string{}})
	if err != nil || c.ReadOnly() || c.PasswordHash != customHash {
		t.Fatalf("locked file must load after it is released: %v readOnly=%v", err, c.ReadOnly())
	}
}
