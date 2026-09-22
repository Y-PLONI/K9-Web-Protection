//go:build windows && !bindings

package main

import "k10webprotection/internal/config"

func loadOptions() config.LoadOptions { return config.LoadOptions{} }
