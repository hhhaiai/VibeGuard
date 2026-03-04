package config

import (
	"strings"
	"unicode"
)

// SanitizePatternValue sanitizes a user-provided pattern value:
// - trim leading/trailing whitespace
// - remove invisible control/format characters (e.g. 0x1F, BOM, zero-width chars)
//
// Goal: avoid "looks the same but doesn't match" issues caused by invisible characters.
func SanitizePatternValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// C0 control characters and DEL.
		if r < 0x20 || r == 0x7f {
			continue
		}
		// Other control/format characters (including common zero-width chars, BOM, etc).
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			continue
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// SanitizeCategory sanitizes and normalizes a category name so placeholders can be reliably recognized and restored.
// Rules:
// - keep only [A-Z0-9_]
// - normalize whitespace and '-' into '_'
// - uppercase; return empty on empty result (caller should apply a default)
func SanitizeCategory(s string) string {
	s = SanitizePatternValue(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastUnderscore := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			r = r - 'a' + 'A'
			b.WriteRune(r)
			lastUnderscore = false
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
			lastUnderscore = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastUnderscore = false
		case r == '_' || r == '-' || unicode.IsSpace(r):
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		default:
			// drop
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return ""
	}
	return out
}

// SanitizeNERLanguage sanitizes and normalizes the NER language parameter (patterns.ner.language).
// Allowed values:
// - auto
// - other BCP47-like tags (e.g. en / zh / zh-cn / fr ...), normalized to lowercase with illegal chars removed
func SanitizeNERLanguage(s string) string {
	s = SanitizePatternValue(s)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	if s == "auto" {
		return "auto"
	}

	// Allow: a-z / 0-9 / '-'; normalize '_' and whitespace into '-'.
	var b strings.Builder
	b.Grow(len(s))
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '-' || r == '_' || unicode.IsSpace(r):
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		default:
			// drop
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return ""
	}
	return out
}
