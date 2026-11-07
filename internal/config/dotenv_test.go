package config

import (
	"maps"
	"os"
	"path/filepath"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    map[string]string
		wantErr bool
	}{
		{"empty", "", map[string]string{}, false},
		{"comments and blanks", "# comment\n\n  # indented\nA=1\n", map[string]string{"A": "1"}, false},
		{"empty value", "CLAUDE_MODEL=\n", map[string]string{"CLAUDE_MODEL": ""}, false},
		{"spaces around", "  A = some value  \n", map[string]string{"A": "some value"}, false},
		{"export prefix", "export A=1", map[string]string{"A": "1"}, false},
		{"crlf", "A=1\r\nB=2\r\n", map[string]string{"A": "1", "B": "2"}, false},
		{"inline comment", "A=1 # note", map[string]string{"A": "1"}, false},
		{"hash without space", "A=https://x.example/#frag", map[string]string{"A": "https://x.example/#frag"}, false},
		{"equals in value", "A=k=v", map[string]string{"A": "k=v"}, false},
		{"double quoted", `A="Digest <d@x.example>" # c`, map[string]string{"A": "Digest <d@x.example>"}, false},
		{"double escapes", `A="a\"b\\c\nd"`, map[string]string{"A": "a\"b\\c\nd"}, false},
		{"double multiline", "A=\"https://a.example\nhttps://b.example\"\nB=2", map[string]string{"A": "https://a.example\nhttps://b.example", "B": "2"}, false},
		{"single quoted literal", `A='a\n "b" # c'`, map[string]string{"A": `a\n "b" # c`}, false},
		{"last wins", "A=1\nA=2", map[string]string{"A": "2"}, false},
		{"no equals", "JUSTAKEY", nil, true},
		{"bad key", "1A=x", nil, true},
		{"space in key", "MY KEY=x", nil, true},
		{"unterminated double", "A=\"abc\nB=2", nil, true},
		{"unterminated single", "A='abc", nil, true},
		{"text after quote", `A="abc"def`, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDotenv(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseDotenv(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if !tt.wantErr && !maps.Equal(got, tt.want) {
				t.Errorf("parseDotenv(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestLoadDotenv(t *testing.T) {
	// t.Setenv restores the original (unset) state after the test.
	t.Setenv("DIGESTOR_TEST_FROM_FILE", "")
	os.Unsetenv("DIGESTOR_TEST_FROM_FILE")
	t.Setenv("DIGESTOR_TEST_FROM_ENV", "env")

	path := filepath.Join(t.TempDir(), ".env")
	data := "DIGESTOR_TEST_FROM_FILE=file\nDIGESTOR_TEST_FROM_ENV=file\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := LoadDotenv(path); err != nil {
		t.Fatalf("LoadDotenv: %v", err)
	}
	if got := os.Getenv("DIGESTOR_TEST_FROM_FILE"); got != "file" {
		t.Errorf("DIGESTOR_TEST_FROM_FILE = %q, want %q", got, "file")
	}
	if got := os.Getenv("DIGESTOR_TEST_FROM_ENV"); got != "env" {
		t.Errorf("DIGESTOR_TEST_FROM_ENV = %q, want the real environment to win", got)
	}

	if err := LoadDotenv(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Errorf("LoadDotenv on a missing file: %v", err)
	}
}
