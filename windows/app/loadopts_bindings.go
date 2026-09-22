//go:build windows && bindings

package main

import (
	"os"
	"path/filepath"

	"k10webprotection/internal/config"
)

// wails generate module runs main(); it must never load (or migrate) the real settings.
func loadOptions() config.LoadOptions {
	return config.LoadOptions{Path: filepath.Join(os.TempDir(), "k10-bindings", "config.json"), LegacyPaths: []string{}}
}
