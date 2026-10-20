package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A credential as webauthn.Credential marshals it: []byte fields are base64.
const testCredential = `{"id":"AQID","publicKey":"BAUG","attestationType":"none","flags":{"userPresent":true,"userVerified":true},"authenticator":{"AAGUID":"","signCount":0}}`

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadPasskeys(t *testing.T) {
	t.Run("one credential per file, empty files and Secret internals skipped", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{
			"iphone":     testCredential + "\n",
			"notesPlain": "",
			"blank":      "  \n",
		})
		// Kubernetes Secret volumes hold their real files under ..data.
		if err := os.Mkdir(filepath.Join(dir, "..data"), 0o700); err != nil {
			t.Fatal(err)
		}
		creds, err := loadPasskeys(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(creds) != 1 || string(creds[0].ID) != "\x01\x02\x03" {
			t.Fatalf("creds = %+v", creds)
		}
	})

	t.Run("invalid credential names the field", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"ipad": "not json"})
		if _, err := loadPasskeys(dir); err == nil || !strings.Contains(err.Error(), "ipad") {
			t.Fatalf("err = %v, want one naming ipad", err)
		}
	})

	t.Run("credential without a public key", func(t *testing.T) {
		dir := writeFiles(t, map[string]string{"mac": `{"id":"AQID"}`})
		if _, err := loadPasskeys(dir); err == nil || !strings.Contains(err.Error(), "mac") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("no passkeys yet", func(t *testing.T) {
		creds, err := loadPasskeys(t.TempDir())
		if err != nil || len(creds) != 0 {
			t.Fatalf("creds = %v, err = %v", creds, err)
		}
	})
}

func TestNewPasskeysOrigins(t *testing.T) {
	for origin, ok := range map[string]bool{
		"https://op-gate.example.com":         true,
		"http://localhost:8080":               true,
		"http://op-gate.example.com":          false,
		"https://op-gate.example.com/approve": false,
		"op-gate.example.com":                 false,
	} {
		if _, err := newPasskeys(origin, nil); (err == nil) != ok {
			t.Errorf("newPasskeys(%q) err = %v, want ok=%v", origin, err, ok)
		}
	}
}
