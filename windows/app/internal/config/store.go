package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const SchemaVersion = 3

// legacySchemaVersion is assumed for files written before settingsVersion existed.
const legacySchemaVersion = 2

type LoadOptions struct {
	Path        string
	LegacyPaths []string
}

type LoadError struct {
	Path string
	Err  error
}

func (e *LoadError) Error() string { return "load " + e.Path + ": " + e.Err.Error() }
func (e *LoadError) Unwrap() error { return e.Err }

type Diagnostics struct {
	Path          string
	Source        string // current | legacy | default
	MigratedFrom  string
	BackupPath    string
	LoadErr       string
	SchemaVersion int // version found on disk before migration
	SkippedLegacy []string
	SkippedRules  []string
}

func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".k10webprotection", "config.json")
}

func LegacyPaths() []string {
	dir := os.Getenv("APPDATA")
	if dir == "" {
		dir, _ = os.UserHomeDir()
	}
	return []string{filepath.Join(dir, "K9WebProtection", "config.json")}
}

func Load() (*Config, error) { return LoadWith(LoadOptions{}) }

func LoadWith(o LoadOptions) (*Config, error) {
	if o.Path == "" {
		o.Path = DefaultPath()
		if o.LegacyPaths == nil {
			o.LegacyPaths = LegacyPaths()
		}
	}
	c, err := load(o)
	c.finish()
	if err != nil {
		return c, err
	}
	return c, nil
}

func load(o LoadOptions) (*Config, *LoadError) {
	data, err := readRetry(o.Path)
	if err == nil {
		return fromFile(o.Path, o.Path, data, "current")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return failClosed(o.Path, o.Path, err)
	}
	for _, lp := range o.LegacyPaths {
		if lp == "" || strings.EqualFold(filepath.Clean(lp), filepath.Clean(o.Path)) {
			continue
		}
		data, err := readRetry(lp)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return failClosed(o.Path, lp, err)
		}
		return fromFile(o.Path, lp, data, "legacy")
	}
	c := newConfig(o.Path)
	c.SettingsVersion = SchemaVersion
	c.diag = Diagnostics{Path: o.Path, Source: "default", SchemaVersion: SchemaVersion}
	return c, nil
}

func fromFile(path, src string, raw []byte, source string) (*Config, *LoadError) {
	data := bytes.TrimPrefix(raw, []byte("\xEF\xBB\xBF"))
	c := newConfig(path)
	if t := bytes.TrimSpace(data); len(t) == 0 || t[0] != '{' {
		return failClosed(path, src, errors.New("not a JSON object"))
	}
	if err := json.Unmarshal(data, c); err != nil {
		return failClosed(path, src, err)
	}
	c.path = path
	c.diag = Diagnostics{Path: path, Source: source, SchemaVersion: c.SettingsVersion}
	if c.diag.SchemaVersion == 0 {
		c.diag.SchemaVersion = legacySchemaVersion
	}
	c.BlockRules, c.diag.SkippedRules = normalizeRules(c.BlockRules)
	allowRules, skipped := normalizeRules(c.AllowRules)
	c.AllowRules, c.diag.SkippedRules = allowRules, append(c.diag.SkippedRules, skipped...)
	if c.SettingsVersion > SchemaVersion {
		// written by a newer version: saving would drop fields this build does not know
		c.readOnly = true
		c.diag.LoadErr = "settings version " + strconv.Itoa(c.SettingsVersion) + " is newer than supported version " + strconv.Itoa(SchemaVersion) + "; opened read-only"
	} else if c.SettingsVersion < SchemaVersion {
		c.migrate(src, raw, src == path)
	}
	return c, nil
}

// failClosed returns protective defaults that cannot be saved and accept no password.
func failClosed(path, src string, err error) (*Config, *LoadError) {
	c := newConfig(path)
	c.PasswordHash = ""
	c.readOnly = true
	c.loadFailed = true
	c.SettingsVersion = SchemaVersion
	le := &LoadError{Path: src, Err: err}
	c.diag = Diagnostics{Path: path, Source: "default", LoadErr: le.Error()}
	return c, le
}

func (c *Config) migrate(src string, raw []byte, inPlace bool) {
	for _, d := range c.UserBlocklist {
		if r, err := ParseRule(d, true); err == nil {
			c.BlockRules = upsertRule(c.BlockRules, r)
		} else {
			c.diag.SkippedLegacy = append(c.diag.SkippedLegacy, d)
		}
	}
	for _, d := range c.UserAllowlist {
		if r, err := ParseRule(d, false); err == nil {
			c.AllowRules = upsertRule(c.AllowRules, r)
		} else {
			c.diag.SkippedLegacy = append(c.diag.SkippedLegacy, d)
		}
	}
	c.UserBlocklist, c.UserAllowlist = nil, nil
	c.SettingsVersion = SchemaVersion
	c.diag.MigratedFrom = src
	if inPlace {
		bp, err := backupFn(src+".v"+strconv.Itoa(c.diag.SchemaVersion)+".bak", raw)
		if err != nil {
			// without a backup the old file must never be overwritten
			c.readOnly = true
			c.diag.LoadErr = "could not back up the settings before upgrading them, so they are read-only: " + err.Error()
			return
		}
		c.diag.BackupPath = bp
	}
	if err := c.Save(); err != nil {
		c.diag.LoadErr = "save migrated config: " + err.Error()
	}
}

var backupFn = writeBackup

// read retries let a briefly locked file (antivirus, sync tools) load instead of failing closed.
const (
	readRetries    = 5
	readRetryDelay = 100 * time.Millisecond
)

func readRetry(path string) ([]byte, error) {
	for i := 0; ; i++ {
		data, err := os.ReadFile(path)
		if err == nil || i >= readRetries || !retryableErr(err) {
			return data, err
		}
		time.Sleep(time.Duration(i+1) * readRetryDelay)
	}
}

func writeBackup(path string, data []byte) (string, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, fs.ErrExist) {
		return path, nil
	}
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(path)
		return "", err
	}
	return path, nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = renameRetry(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

func renameRetry(from, to string) error {
	var err error
	for i := 0; i < 10; i++ {
		if err = os.Rename(from, to); err == nil || !retryableErr(err) {
			return err
		}
		time.Sleep(time.Duration(i+1) * 10 * time.Millisecond)
	}
	return err
}

func retryableErr(err error) bool {
	var errno syscall.Errno
	if runtime.GOOS != "windows" || !errors.As(err, &errno) {
		return false
	}
	// ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
	return errno == 5 || errno == 32 || errno == 33
}

func (c *Config) Diagnostics() Diagnostics {
	c.mu.RLock()
	defer c.mu.RUnlock()
	d := c.diag
	d.SkippedLegacy = append([]string(nil), c.diag.SkippedLegacy...)
	d.SkippedRules = append([]string(nil), c.diag.SkippedRules...)
	return d
}

func (c *Config) ReadOnly() bool { return c.readOnly }

// LoadFailed reports that the file could not be read or parsed, so the config holds only defaults.
func (c *Config) LoadFailed() bool { return c.loadFailed }

func (c *Config) Path() string { return c.path }
