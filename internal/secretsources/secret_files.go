package secretsources

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/keywords"
)

const maxSecretFileBytes = 1 << 20 // 1 MiB

var dotenvKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// LoadKeywords imports secret values from configured files and returns them as keyword patterns.
// It is best-effort: a single failing source does not stop others.
func LoadKeywords(sources []config.SecretFileConfig) ([]keywords.Keyword, []error) {
	if len(sources) == 0 {
		return nil, nil
	}

	seen := make(map[string]struct{}, 1024)
	out := make([]keywords.Keyword, 0, 128)
	var warns []error

	for _, src := range sources {
		enabled := true
		if src.Enabled != nil {
			enabled = *src.Enabled
		}
		if !enabled {
			continue
		}

		path := strings.TrimSpace(src.Path)
		if path == "" {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			warns = append(warns, fmt.Errorf("secret_files: read %q: %w", path, err))
			continue
		}
		if len(data) > maxSecretFileBytes {
			warns = append(warns, fmt.Errorf("secret_files: %q too large (%d bytes > %d bytes), skipped", path, len(data), maxSecretFileBytes))
			continue
		}

		format := strings.ToLower(strings.TrimSpace(src.Format))
		if format == "" {
			format = "dotenv"
		}

		cat := config.SanitizeCategory(src.Category)
		if cat == "" {
			cat = "DOTENV"
			if format == "lines" {
				cat = "SECRET_FILE"
			}
		}

		minLen := src.MinValueLen
		if minLen <= 0 {
			minLen = 8
		}

		var values []string
		switch format {
		case "dotenv":
			values, err = parseDotenvValues(data, minLen)
		case "lines":
			values, err = parseLineValues(data, minLen)
		default:
			err = fmt.Errorf("unknown format %q", format)
		}
		if err != nil {
			warns = append(warns, fmt.Errorf("secret_files: parse %q: %w", path, err))
			continue
		}

		for _, v := range values {
			v = config.SanitizePatternValue(v)
			if v == "" {
				continue
			}
			if _, ok := seen[v]; ok {
				continue
			}
			seen[v] = struct{}{}
			out = append(out, keywords.Keyword{Text: v, Category: cat})
		}
	}

	return out, warns
}

func parseLineValues(data []byte, minLen int) ([]string, error) {
	var out []string
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(strings.TrimRight(s.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) < minLen {
			continue
		}
		out = append(out, line)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseDotenvValues(data []byte, minLen int) ([]string, error) {
	var out []string
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := strings.TrimSpace(strings.TrimRight(s.Text(), "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}

		key := strings.TrimSpace(line[:eq])
		if key == "" || !dotenvKeyRe.MatchString(key) {
			continue
		}

		raw := strings.TrimSpace(line[eq+1:])
		if raw == "" {
			continue
		}

		val, ok, err := parseDotenvValue(raw)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if len(val) < minLen {
			continue
		}
		out = append(out, val)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func parseDotenvValue(raw string) (string, bool, error) {
	if raw == "" {
		return "", false, nil
	}

	switch raw[0] {
	case '"':
		// Double-quoted: allow common escapes.
		v, rest, ok := parseQuoted(raw, '"')
		if !ok {
			return "", false, errors.New("unterminated double-quoted value")
		}
		_ = rest // Comments after a quoted value are ignored.
		v = strings.ReplaceAll(v, `\\`, `\`)
		v = strings.ReplaceAll(v, `\n`, "\n")
		v = strings.ReplaceAll(v, `\r`, "\r")
		v = strings.ReplaceAll(v, `\t`, "\t")
		v = strings.ReplaceAll(v, `\"`, `"`)
		return v, true, nil
	case '\'':
		// Single-quoted: no escapes.
		v, rest, ok := parseQuoted(raw, '\'')
		if !ok {
			return "", false, errors.New("unterminated single-quoted value")
		}
		_ = rest
		return v, true, nil
	default:
		// Unquoted: strip inline comments (FOO=bar # comment).
		v := raw
		if i := indexInlineComment(v); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		return v, v != "", nil
	}
}

func parseQuoted(s string, quote byte) (value string, rest string, ok bool) {
	if len(s) == 0 || s[0] != quote {
		return "", s, false
	}
	// Find the next unescaped quote for double-quoted, or the next quote for single-quoted.
	if quote == '\'' {
		i := strings.IndexByte(s[1:], quote)
		if i < 0 {
			return "", s, false
		}
		end := 1 + i
		return s[1:end], s[end+1:], true
	}

	var b strings.Builder
	escaped := false
	for i := 1; i < len(s); i++ {
		ch := s[i]
		if escaped {
			b.WriteByte('\\')
			b.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == quote {
			return b.String(), s[i+1:], true
		}
		b.WriteByte(ch)
	}
	return "", s, false
}

func indexInlineComment(s string) int {
	// A conservative heuristic: treat " #" (space + #) as the start of an inline comment.
	for i := 0; i < len(s); i++ {
		if s[i] != '#' {
			continue
		}
		if i == 0 {
			return 0
		}
		if isSpace(s[i-1]) {
			return i
		}
	}
	return -1
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t'
}
