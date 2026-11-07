package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
)

// LoadDotenv sets environment variables from the dotenv file at path. A
// variable that is already set keeps its value, so the real environment
// overrides the file. A missing file is not an error.
func LoadDotenv(path string) error {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		slog.Debug("no dotenv file", "path", path)
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading dotenv file: %w", err)
	}

	vars, err := parseDotenv(string(data))
	if err != nil {
		return fmt.Errorf("parsing dotenv file %s: %w", path, err)
	}

	set, kept := 0, 0
	for k, v := range vars {
		if _, ok := os.LookupEnv(k); ok {
			kept++
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			return fmt.Errorf("setting %s: %w", k, err)
		}
		set++
	}
	slog.Info("loaded dotenv file", "path", path, "set", set, "already_in_env", kept)
	return nil
}

// parseDotenv reads KEY=VALUE lines. Blank lines and lines starting with #
// are skipped, and an "export " prefix is allowed. Values may be unquoted
// (a " #" starts a comment), single-quoted (taken literally) or
// double-quoted (may span lines; \n, \" and \\ are unescaped). A key that
// appears twice takes its last value.
func parseDotenv(s string) (map[string]string, error) {
	vars := make(map[string]string)
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")

	for i := 0; i < len(lines); i++ {
		lineNo := i + 1
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")

		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !validKey(key) {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", lineNo)
		}
		value = strings.TrimSpace(value)

		switch {
		case strings.HasPrefix(value, `"`):
			raw := value[1:]
			for {
				v, rest, closed := unquoteDouble(raw)
				if closed {
					if !isComment(rest) {
						return nil, fmt.Errorf("line %d: unexpected text after closing quote", lineNo)
					}
					value = v
					break
				}
				if i+1 >= len(lines) {
					return nil, fmt.Errorf("line %d: unterminated double quote", lineNo)
				}
				i++
				raw += "\n" + lines[i]
			}
		case strings.HasPrefix(value, "'"):
			v, rest, closed := strings.Cut(value[1:], "'")
			if !closed {
				return nil, fmt.Errorf("line %d: unterminated single quote", lineNo)
			}
			if !isComment(rest) {
				return nil, fmt.Errorf("line %d: unexpected text after closing quote", lineNo)
			}
			value = v
		default:
			if j := strings.Index(value, " #"); j >= 0 {
				value = strings.TrimSpace(value[:j])
			}
		}
		vars[key] = value
	}
	return vars, nil
}

// unquoteDouble reads s up to the first unescaped double quote. It returns
// the unescaped value, the text after the quote and whether a quote was found.
func unquoteDouble(s string) (value, rest string, closed bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '"':
			return b.String(), s[i+1:], true
		case c == '\\' && i+1 < len(s):
			i++
			if s[i] == 'n' {
				b.WriteByte('\n')
			} else {
				b.WriteByte(s[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return "", "", false
}

// isComment reports whether s, the text after a closing quote, is empty or a
// comment.
func isComment(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || strings.HasPrefix(s, "#")
}

func validKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		switch {
		case r == '_', r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}
