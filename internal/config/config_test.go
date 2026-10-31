package config

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

const secret = "0123456789abcdef0123456789abcdef"

func TestDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"RELAY_SECRET": secret}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":8080" || c.Registration != RegOpen || c.HubRate != 120 || c.FCMKey != nil || c.TrustProxy {
		t.Fatalf("%+v", c)
	}
}

func TestErrors(t *testing.T) {
	for _, m := range []map[string]string{
		{},
		{"RELAY_SECRET": "short"},
		{"RELAY_SECRET": secret, "RELAY_REGISTRATION": "maybe"},
		{"RELAY_SECRET": secret, "RELAY_REGISTRATION": "token"},
		{"RELAY_SECRET": secret, "RELAY_HUB_RATE": "-1"},
		{"RELAY_SECRET": secret, "RELAY_TRUST_PROXY": "yes please"},
		{"RELAY_SECRET": secret, "FCM_CREDENTIALS": "not base64!"},
		{"RELAY_SECRET_FILE": "/does/not/exist"},
	} {
		if _, err := Load(env(m)); err == nil {
			t.Fatalf("%v: want error", m)
		}
	}
}

func TestFilesAndBase64(t *testing.T) {
	dir := t.TempDir()
	sf := filepath.Join(dir, "secret")
	os.WriteFile(sf, []byte(secret+"\n"), 0o600)
	js := `{"type":"service_account"}`
	c, err := Load(env(map[string]string{
		"RELAY_SECRET_FILE":  sf,
		"FCM_CREDENTIALS":    base64.StdEncoding.EncodeToString([]byte(js)),
		"RELAY_REVOKED_HUBS": " a, b ,,",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if string(c.Secret) != secret || string(c.FCMKey) != js || !c.RevokedHubs["a"] || !c.RevokedHubs["b"] || len(c.RevokedHubs) != 2 {
		t.Fatalf("%+v", c)
	}
}
