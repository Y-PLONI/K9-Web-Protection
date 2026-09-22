// Package i18n is a tiny, dependency-free message catalog for the Go backend.
//
// Usage:
//
//	i18n.SetLang(cfg.Language)      // once, at startup
//	i18n.T("err.invalidDomain")     // plain lookup
//	i18n.T("err.focusModeActive", 5) // fmt.Sprintf-style args
//
// Lookup order: active language → "en" → the key itself.
package i18n

import (
	"fmt"
	"sync"
)

// DefaultLang is used when no language has been configured.
const DefaultLang = "he"

// FallbackLang always exists in the catalog and is used for missing keys.
const FallbackLang = "en"

var (
	mu      sync.RWMutex
	current = DefaultLang
)

// SetLang selects the active language. An unknown or empty language falls back
// to FallbackLang.
func SetLang(lang string) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := catalog[lang]; ok {
		current = lang
		return
	}
	current = FallbackLang
}

// Lang returns the active language code (suitable for an HTML lang attribute).
func Lang() string {
	mu.RLock()
	defer mu.RUnlock()
	return current
}

// Dir returns the text direction of the active language ("rtl" or "ltr"),
// suitable for an HTML dir attribute.
func Dir() string {
	if Lang() == "he" {
		return "rtl"
	}
	return "ltr"
}

// T returns the message for key in the active language. Any args are applied
// with fmt.Sprintf. Missing keys fall back to English and then to the key.
func T(key string, args ...any) string {
	mu.RLock()
	lang := current
	mu.RUnlock()

	s, ok := catalog[lang][key]
	if !ok || s == "" {
		s, ok = catalog[FallbackLang][key]
	}
	if !ok || s == "" {
		s = key
	}
	if len(args) > 0 {
		return fmt.Sprintf(s, args...)
	}
	return s
}

// catalog maps language code → message key → text.
//
// NOTE FOR TRANSLATORS: the "he" block below is currently an exact copy of the
// "en" block. Translate the "he" values only; never change a key, and keep every
// fmt verb (%s, %d, %.0f, %v) in place and in the same order.
var catalog = map[string]map[string]string{
	"en": {
		// ── Application chrome ────────────────────────────────────────────
		"app.title":       "K10 Web Protection",
		"app.productName": "K10 Web Protection",

		// ── app.go errors surfaced as UI toasts ───────────────────────────
		"err.incorrectPassword":        "incorrect password",
		"err.incorrectCurrentPassword": "incorrect current password",
		"err.focusModeActive":          "focus mode is active — %d min remaining",
		"err.disableDelayActive":       "disable delay active — %.0f hours remaining",
		"err.noDelayConfigured":        "no delay configured",
		"err.invalidDomain":            "invalid domain",
		"err.emptyKeyword":             "empty keyword",
		"err.portRange":                "port must be between 1024 and 65535",
		"err.unsupportedLanguage":      "unsupported language",
		"err.focusDurationRange":       "duration must be between 1 and 1440 minutes",
		"err.prepareUninstallScript":   "could not prepare uninstall script",
		"err.uninstallNeedsAdmin":      "administrator privileges required to complete uninstall",
		"err.prepareInstallScript":     "could not prepare install script",
		"err.caInstallNeedsAdmin":      "administrator access required to install CA certificate",
		"err.caCertNotFound":           "CA certificate not found — enable protection first",
		"err.proxyFailedToStart":       "proxy failed to start",
		"err.proxyStartTimeout":        "proxy did not start on port %d within 5 seconds",

		// ── Defaults stored in config.json ────────────────────────────────
		"config.blockedMessageDefault": "This website has been blocked to help you stay focused and protected.",

		// ── HTTPS/HTTP block page ─────────────────────────────────────────
		"block.pageTitle":   "Blocked — K10 Web Protection",
		"block.headerTitle": "K10 Web Protection Administration",
		"block.chip":        "Access Blocked",
		"block.heading":     "This website has been blocked",
		"block.siteLabel":   "Site:",
		"block.message": "This website has been blocked by K10 Web Protection because it may contain adult content, malware, phishing attempts, or other material that violates your configured filtering policy.",
		"block.chipFiltered": "Filtered by K10 Web Protection",
		"block.chipContact":  "Contact your administrator to request access",
		"block.copyright":    "Copyright &copy; 2024&ndash;2026 K10WebProtection &mdash; All Rights Reserved.",

		// -- macOS-only errors ---------------------------------------------
		"err.invalidCertFormat":  "invalid certificate format",
		"err.writeProfileFailed": "failed to write profile",
		"err.openProfileFailed":  "failed to open profile installer",

		// -- macOS configuration profile (.mobileconfig), shown by System Settings --
		"profile.caDisplayName": "K10 Web Protection CA",
		"profile.caDescription": "K10 Web Protection root CA",
		"profile.organization":  "K10 Web Protection",
		"profile.displayName":   "K10 Web Protection Certificate",
		"profile.description":   "Installs the K10 Web Protection CA so HTTPS block pages display correctly in all browsers.",
	},

	// Hebrew — placeholder copy of English, to be filled by the translator.
	"he": {
		// ── Application chrome ────────────────────────────────────────────
		"app.title":       "K10 Web Protection",
		"app.productName": "K10 Web Protection",

		// ── app.go errors surfaced as UI toasts ───────────────────────────
		"err.incorrectPassword":        "incorrect password",
		"err.incorrectCurrentPassword": "incorrect current password",
		"err.focusModeActive":          "focus mode is active — %d min remaining",
		"err.disableDelayActive":       "disable delay active — %.0f hours remaining",
		"err.noDelayConfigured":        "no delay configured",
		"err.invalidDomain":            "invalid domain",
		"err.emptyKeyword":             "empty keyword",
		"err.portRange":                "port must be between 1024 and 65535",
		"err.unsupportedLanguage":      "unsupported language",
		"err.focusDurationRange":       "duration must be between 1 and 1440 minutes",
		"err.prepareUninstallScript":   "could not prepare uninstall script",
		"err.uninstallNeedsAdmin":      "administrator privileges required to complete uninstall",
		"err.prepareInstallScript":     "could not prepare install script",
		"err.caInstallNeedsAdmin":      "administrator access required to install CA certificate",
		"err.caCertNotFound":           "CA certificate not found — enable protection first",
		"err.proxyFailedToStart":       "proxy failed to start",
		"err.proxyStartTimeout":        "proxy did not start on port %d within 5 seconds",

		// ── Defaults stored in config.json ────────────────────────────────
		"config.blockedMessageDefault": "This website has been blocked to help you stay focused and protected.",

		// ── HTTPS/HTTP block page ─────────────────────────────────────────
		"block.pageTitle":   "Blocked — K10 Web Protection",
		"block.headerTitle": "K10 Web Protection Administration",
		"block.chip":        "Access Blocked",
		"block.heading":     "This website has been blocked",
		"block.siteLabel":   "Site:",
		"block.message": "This website has been blocked by K10 Web Protection because it may contain adult content, malware, phishing attempts, or other material that violates your configured filtering policy.",
		"block.chipFiltered": "Filtered by K10 Web Protection",
		"block.chipContact":  "Contact your administrator to request access",
		"block.copyright":    "Copyright &copy; 2024&ndash;2026 K10WebProtection &mdash; All Rights Reserved.",

		// -- macOS-only errors ---------------------------------------------
		"err.invalidCertFormat":  "invalid certificate format",
		"err.writeProfileFailed": "failed to write profile",
		"err.openProfileFailed":  "failed to open profile installer",

		// -- macOS configuration profile (.mobileconfig), shown by System Settings --
		"profile.caDisplayName": "K10 Web Protection CA",
		"profile.caDescription": "K10 Web Protection root CA",
		"profile.organization":  "K10 Web Protection",
		"profile.displayName":   "K10 Web Protection Certificate",
		"profile.description":   "Installs the K10 Web Protection CA so HTTPS block pages display correctly in all browsers.",
	},
}
