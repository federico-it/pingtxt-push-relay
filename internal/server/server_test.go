package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/federico-it/pingtxt-push-relay/internal/config"
	"github.com/federico-it/pingtxt-push-relay/internal/fcm"
	"github.com/federico-it/pingtxt-push-relay/internal/keys"
)

type fakeSender struct {
	mu   sync.Mutex
	sent []fcm.Message
	errs map[string]error // by FCM token
}

func (f *fakeSender) Send(_ context.Context, m fcm.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errs[m.Token]; err != nil {
		return err
	}
	f.sent = append(f.sent, m)
	return nil
}

type env struct {
	t    *testing.T
	srv  *httptest.Server
	keys *keys.Keys
	fcm  *fakeSender
	cfg  *config.Config
}

func setup(t *testing.T, mod func(*config.Config)) *env {
	t.Helper()
	cfg, err := config.Load(func(k string) string {
		if k == "RELAY_SECRET" {
			return "0123456789abcdef0123456789abcdef"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if mod != nil {
		mod(cfg)
	}
	k, err := keys.New(cfg.Secret)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSender{errs: map[string]error{}}
	s := New(cfg, k, f, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, srv: ts, keys: k, fcm: f, cfg: cfg}
}

func (e *env) do(method, path, token string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) register() (string, string) {
	e.t.Helper()
	code, out := e.do("POST", "/v1/hubs", "", nil)
	if code != 201 {
		e.t.Fatalf("register: %d %v", code, out)
	}
	return out["hub_id"].(string), out["hub_token"].(string)
}

func (e *env) enroll(hubID, fcmToken string) string {
	e.t.Helper()
	code, out := e.do("POST", "/v1/devices", "", map[string]string{"hub_id": hubID, "fcm_token": fcmToken})
	if code != 201 {
		e.t.Fatalf("enroll: %d %v", code, out)
	}
	return out["device"].(string)
}

func TestHealthAndIndex(t *testing.T) {
	e := setup(t, nil)
	if code, out := e.do("GET", "/healthz", "", nil); code != 200 || out["status"] != "ok" || out["fcm"] != true {
		t.Fatalf("%d %v", code, out)
	}
	if code, out := e.do("GET", "/", "", nil); code != 200 || out["version"] != "test" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestFlow(t *testing.T) {
	e := setup(t, nil)
	hubID, hubTok := e.register()
	if code, out := e.do("GET", "/v1/hubs/me", hubTok, nil); code != 200 || out["hub_id"] != hubID {
		t.Fatalf("me: %d %v", code, out)
	}
	d1 := e.enroll(hubID, "tok-1")
	d2 := e.enroll(hubID, "tok-2")
	e.fcm.errs["tok-2"] = fmt.Errorf("x: %w", fcm.ErrUnregistered)

	otherID, _ := e.register()
	dOther := e.enroll(otherID, "tok-3")

	code, out := e.do("POST", "/v1/push", hubTok, map[string]any{
		"devices": []string{d1, d2, dOther, "prd_garbage"}, "title": "api: down", "body": "timeout after 10s",
		"priority": "high", "collapse_id": "monitor-1", "data": map[string]string{"monitor_id": "1"},
	})
	if code != 200 {
		t.Fatalf("push: %d %v", code, out)
	}
	got := map[string]string{}
	for _, r := range out["results"].([]any) {
		m := r.(map[string]any)
		got[m["device"].(string)] = m["status"].(string)
	}
	want := map[string]string{d1: StatusSent, d2: StatusGone, dOther: StatusGone, "prd_garbage": StatusGone}
	for d, s := range want {
		if got[d] != s {
			t.Fatalf("%s: got %s, want %s (%v)", d[:12], got[d], s, got)
		}
	}
	if len(e.fcm.sent) != 1 {
		t.Fatalf("%d sent", len(e.fcm.sent))
	}
	m := e.fcm.sent[0]
	if m.Token != "tok-1" || !m.HighPrio || m.CollapseID != "monitor-1" || m.Data["monitor_id"] != "1" {
		t.Fatalf("%+v", m)
	}
}

func TestPushAuth(t *testing.T) {
	e := setup(t, nil)
	hubID, hubTok := e.register()
	body := map[string]any{"devices": []string{"prd_x"}, "title": "t"}
	if code, _ := e.do("POST", "/v1/push", "", body); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := e.do("POST", "/v1/push", hubTok+"x", body); code != 401 {
		t.Fatalf("bad token: %d", code)
	}
	e.cfg.RevokedHubs[hubID] = true
	if code, _ := e.do("POST", "/v1/push", hubTok, body); code != 403 {
		t.Fatalf("revoked: %d", code)
	}
	if code, _ := e.do("POST", "/v1/devices", "", map[string]string{"hub_id": hubID, "fcm_token": "t"}); code != 403 {
		t.Fatalf("enroll revoked: %d", code)
	}
}

func TestPushValidation(t *testing.T) {
	e := setup(t, nil)
	hubID, hubTok := e.register()
	d := e.enroll(hubID, "tok")
	many := make([]string, 101)
	for i := range many {
		many[i] = fmt.Sprint("prd_", i)
	}
	bigData := map[string]string{"k": strings.Repeat("v", 3000)}
	for name, body := range map[string]map[string]any{
		"no devices":  {"title": "t"},
		"too many":    {"devices": many, "title": "t"},
		"duplicate":   {"devices": []string{d, d}, "title": "t"},
		"no title":    {"devices": []string{d}},
		"long body":   {"devices": []string{d}, "title": "t", "body": strings.Repeat("b", 2001)},
		"reserved":    {"devices": []string{d}, "title": "t", "data": map[string]string{"google.x": "1"}},
		"big data":    {"devices": []string{d}, "title": "t", "data": bigData},
		"priority":    {"devices": []string{d}, "title": "t", "priority": "urgent"},
		"ttl":         {"devices": []string{d}, "title": "t", "ttl": -1},
		"long thread": {"devices": []string{d}, "title": "t", "thread_id": strings.Repeat("x", 65)},
	} {
		if code, out := e.do("POST", "/v1/push", hubTok, body); code != 400 {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	// Not JSON.
	req, _ := http.NewRequest("POST", e.srv.URL+"/v1/push", strings.NewReader("{"))
	req.Header.Set("Authorization", "Bearer "+hubTok)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("bad json: %d", resp.StatusCode)
	}
}

func TestRateLimits(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.DeviceRate = 6; c.IPRate = 4 })
	hubID, hubTok := e.register()
	d := e.enroll(hubID, "tok")
	statuses := map[string]int{}
	for range 10 {
		_, out := e.do("POST", "/v1/push", hubTok, map[string]any{"devices": []string{d}, "title": "t"})
		statuses[out["results"].([]any)[0].(map[string]any)["status"].(string)]++
	}
	if statuses[StatusSent] != 5 || statuses[StatusRateLimited] != 5 {
		t.Fatalf("device limit: %v", statuses)
	}
	// 2 IP calls used above; burst is 5.
	limited := false
	for range 5 {
		if code, _ := e.do("POST", "/v1/hubs", "", nil); code == 429 {
			limited = true
		}
	}
	if !limited {
		t.Fatal("ip limit not applied")
	}
}

func TestHubRateLimit(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.HubRate = 1; c.IPRate = 0 })
	hubID, hubTok := e.register()
	devs := make([]string, 60)
	for i := range devs {
		devs[i] = e.enroll(hubID, fmt.Sprint("tok-", i))
	}
	if code, _ := e.do("POST", "/v1/push", hubTok, map[string]any{"devices": devs, "title": "t"}); code != 200 {
		t.Fatalf("first: %d", code)
	}
	if code, _ := e.do("POST", "/v1/push", hubTok, map[string]any{"devices": devs, "title": "t"}); code != 429 {
		t.Fatalf("second: %d", code)
	}
}

func TestRegistrationModes(t *testing.T) {
	e := setup(t, func(c *config.Config) { c.Registration = config.RegClosed })
	if code, _ := e.do("POST", "/v1/hubs", "", nil); code != 403 {
		t.Fatalf("closed: %d", code)
	}
	e = setup(t, func(c *config.Config) { c.Registration = config.RegToken; c.RegToken = "registration-secret" })
	if code, _ := e.do("POST", "/v1/hubs", "", nil); code != 401 {
		t.Fatalf("token missing: %d", code)
	}
	if code, _ := e.do("POST", "/v1/hubs", "registration-secret", nil); code != 201 {
		t.Fatalf("token ok: %d", code)
	}
}

func TestNoFCM(t *testing.T) {
	e := setup(t, nil)
	s := New(e.cfg, e.keys, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	e.srv = ts
	_, hubTok := e.register()
	if code, _ := e.do("POST", "/v1/push", hubTok, map[string]any{"devices": []string{"prd_x"}, "title": "t"}); code != 503 {
		t.Fatalf("%d", code)
	}
}

func TestClientIP(t *testing.T) {
	s := &Server{cfg: &config.Config{}}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2")
	if ip := s.clientIP(r); ip != "10.0.0.1" {
		t.Fatal(ip)
	}
	s.cfg.TrustProxy = true
	if ip := s.clientIP(r); ip != "2.2.2.2" {
		t.Fatal(ip)
	}
	s.cfg.ClientIPHeader = "CF-Connecting-IP"
	if ip := s.clientIP(r); ip != "2.2.2.2" {
		t.Fatal("no header:", ip)
	}
	r.Header.Set("CF-Connecting-IP", "not an ip")
	if ip := s.clientIP(r); ip != "2.2.2.2" {
		t.Fatal("bad header:", ip)
	}
	r.Header.Set("CF-Connecting-IP", "2001:db8::1")
	if ip := s.clientIP(r); ip != "2001:db8::1" {
		t.Fatal(ip)
	}
}

func TestLiveActivity(t *testing.T) {
	e := setup(t, nil)
	hubID, hubTok := e.register()
	d1 := e.enroll(hubID, "tok-1")
	d2 := e.enroll(hubID, "tok-2")
	e.fcm.errs["tok-2"] = fmt.Errorf("x: %w", fcm.ErrUnregistered)
	la1, la2 := strings.Repeat("ab", 40), strings.Repeat("cd", 40)

	code, out := e.do("POST", "/v1/live-activity", hubTok, map[string]any{
		"event": "start", "content_state": map[string]any{"count": 1}, "attributes_type": "OutageActivityAttributes",
		"attributes": map[string]string{"hub": "https://h"}, "stale_date": 1_800_000_000, "title": "api is down",
		"targets": []map[string]string{{"device": d1, "token": la1}, {"device": d2, "token": la2}, {"device": "prd_bad", "token": strings.Repeat("ef", 40)}},
	})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	res := out["results"].([]any)
	want := []string{StatusSent, StatusGone, StatusDeviceGone}
	for i, w := range want {
		if s := res[i].(map[string]any)["status"]; s != w {
			t.Fatalf("result %d: %v, want %s", i, s, w)
		}
	}
	if len(e.fcm.sent) != 1 {
		t.Fatalf("%d sent", len(e.fcm.sent))
	}
	m := e.fcm.sent[0]
	la := m.LiveActivity
	if m.Token != "tok-1" || !m.HighPrio || !m.Silent || m.Title != "api is down" || la == nil || la.Token != la1 ||
		la.Event != "start" || la.AttributesType != "OutageActivityAttributes" || la.StaleDate.Unix() != 1_800_000_000 ||
		string(la.ContentState) != `{"count":1}` {
		t.Fatalf("%+v %+v", m, la)
	}

	// Update: attributes are dropped, priority normal kept.
	code, out = e.do("POST", "/v1/live-activity", hubTok, map[string]any{
		"event": "update", "content_state": map[string]any{"count": 2}, "priority": "normal",
		"attributes": map[string]string{"hub": "x"}, "targets": []map[string]string{{"device": d1, "token": la1}},
	})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if m := e.fcm.sent[1]; m.HighPrio || m.LiveActivity.Attributes != nil || m.LiveActivity.Event != "update" {
		t.Fatalf("%+v", m)
	}

	bad := []map[string]any{
		{"event": "pause", "content_state": map[string]any{}, "targets": []map[string]string{{"device": d1, "token": la1}}},
		{"event": "update", "content_state": map[string]any{}, "targets": []map[string]string{}},
		{"event": "update", "content_state": map[string]any{}, "targets": []map[string]string{{"device": d1, "token": "not-hex-token-xyz"}}},
		{"event": "update", "content_state": []int{1}, "targets": []map[string]string{{"device": d1, "token": la1}}},
		{"event": "update", "content_state": map[string]any{}, "targets": []map[string]string{{"device": d1, "token": la1}, {"device": d2, "token": la1}}},
		{"event": "start", "content_state": map[string]any{}, "targets": []map[string]string{{"device": d1, "token": la1}}},
		{"event": "update", "content_state": map[string]any{"x": strings.Repeat("a", 3000)}, "targets": []map[string]string{{"device": d1, "token": la1}}},
	}
	for i, b := range bad {
		if code, out := e.do("POST", "/v1/live-activity", hubTok, b); code != 400 {
			t.Fatalf("bad %d: %d %v", i, code, out)
		}
	}
	if code, _ := e.do("POST", "/v1/live-activity", "", bad[0]); code != 401 {
		t.Fatalf("no token: %d", code)
	}
}
