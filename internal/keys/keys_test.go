package keys

import (
	"bytes"
	"strings"
	"testing"
)

func newKeys(t *testing.T, b byte) *Keys {
	t.Helper()
	k, err := New(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewRejectsShortSecret(t *testing.T) {
	if _, err := New([]byte("short")); err == nil {
		t.Fatal("want error")
	}
}

func TestHubToken(t *testing.T) {
	k := newKeys(t, 1)
	id, tok := k.NewHub()
	if !strings.HasPrefix(tok, HubTokenPrefix) {
		t.Fatalf("token %q", tok)
	}
	got, err := k.CheckHubToken(tok)
	if err != nil || got != id {
		t.Fatalf("got %q, %v", got, err)
	}
	other := newKeys(t, 2)
	if _, err := other.CheckHubToken(tok); err == nil {
		t.Fatal("token accepted with another secret")
	}
	for _, bad := range []string{"", "prh_", tok + "x", strings.Replace(tok, ".", "", 1), "abc" + tok, tok[:len(tok)-2]} {
		if _, err := k.CheckHubToken(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	// Another hub id with the MAC of the first one.
	id2, _ := k.NewHub()
	forged := HubTokenPrefix + id2 + tok[strings.Index(tok, "."):]
	if _, err := k.CheckHubToken(forged); err == nil {
		t.Fatal("forged token accepted")
	}
}

func TestDeviceHandle(t *testing.T) {
	k := newKeys(t, 1)
	hubA, _ := k.NewHub()
	hubB, _ := k.NewHub()
	h, err := k.SealDevice(hubA, "fcm-token-123")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(h, "fcm-token") {
		t.Fatal("handle shows the token")
	}
	tok, err := k.OpenDevice(hubA, h)
	if err != nil || tok != "fcm-token-123" {
		t.Fatalf("got %q, %v", tok, err)
	}
	if _, err := k.OpenDevice(hubB, h); err == nil {
		t.Fatal("handle opened by another hub")
	}
	if _, err := newKeys(t, 2).OpenDevice(hubA, h); err == nil {
		t.Fatal("handle opened with another secret")
	}
	// Two handles of the same token differ (random nonce).
	h2, _ := k.SealDevice(hubA, "fcm-token-123")
	if h == h2 {
		t.Fatal("handles are equal")
	}
	// Tampering.
	b := []byte(h)
	b[len(b)/2] ^= 1
	for _, bad := range []string{"", "prd_", "prd_AAAA", string(b), h[4:]} {
		if _, err := k.OpenDevice(hubA, bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestSealDeviceValidates(t *testing.T) {
	k := newKeys(t, 1)
	hub, _ := k.NewHub()
	if _, err := k.SealDevice("nope", "tok"); err == nil {
		t.Fatal("bad hub id accepted")
	}
	if _, err := k.SealDevice(hub, ""); err == nil {
		t.Fatal("empty token accepted")
	}
	if _, err := k.SealDevice(hub, strings.Repeat("a", maxFCMToken+1)); err == nil {
		t.Fatal("long token accepted")
	}
}
