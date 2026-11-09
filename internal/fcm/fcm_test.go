package fcm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fake struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	tokens    atomic.Int32
	sends     atomic.Int32
	last      atomic.Value // map[string]any
	sendReply func(n int32) (int, string)
}

func newFake(t *testing.T) *fake {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{key: key}
	f.sendReply = func(int32) (int, string) { return 200, `{"name":"projects/p/messages/1"}` }
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			b, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(b))
			parts := strings.Split(form.Get("assertion"), ".")
			if len(parts) != 3 {
				http.Error(w, "bad jwt", 400)
				return
			}
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
				http.Error(w, "bad signature", 400)
				return
			}
			n := f.tokens.Add(1)
			w.Write([]byte(`{"access_token":"at-` + string(rune('0'+n)) + `","expires_in":3600}`))
		case "/v1/projects/proj/messages:send":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer at-") {
				http.Error(w, "no auth", 401)
				return
			}
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			f.last.Store(body)
			code, reply := f.sendReply(f.sends.Add(1))
			w.WriteHeader(code)
			w.Write([]byte(reply))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) client(t *testing.T) *Client {
	t.Helper()
	der, _ := x509.MarshalPKCS8PrivateKey(f.key)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	js, _ := json.Marshal(map[string]string{
		"type": "service_account", "project_id": "proj", "private_key": pemKey,
		"client_email": "relay@proj.iam.gserviceaccount.com", "token_uri": f.srv.URL + "/token",
	})
	sa, err := ParseServiceAccount(js)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(sa, Options{APIBase: f.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestParseServiceAccount(t *testing.T) {
	if _, err := ParseServiceAccount([]byte(`{"type":"authorized_user"}`)); err == nil {
		t.Fatal("want error")
	}
	if _, err := ParseServiceAccount([]byte(`nope`)); err == nil {
		t.Fatal("want error")
	}
}

func TestSendAndTokenCache(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	ctx := context.Background()
	m := Message{Token: "dev", Title: "api down", Body: "timeout", HighPrio: true, CollapseID: "m-1",
		ThreadID: "m-1", Category: "MONITOR_DOWN", TTL: time.Hour, Data: map[string]string{"monitor_id": "1"}}
	for range 3 {
		if err := c.Send(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokens.Load() != 1 {
		t.Fatalf("%d token requests, want 1 (cache)", f.tokens.Load())
	}
	body := f.last.Load().(map[string]any)
	msg := body["message"].(map[string]any)
	if msg["token"] != "dev" {
		t.Fatalf("token %v", msg["token"])
	}
	apns := msg["apns"].(map[string]any)
	h := apns["headers"].(map[string]any)
	if h["apns-priority"] != "10" || h["apns-collapse-id"] != "m-1" || h["apns-expiration"] == nil {
		t.Fatalf("headers %v", h)
	}
	aps := apns["payload"].(map[string]any)["aps"].(map[string]any)
	if aps["sound"] != "default" || aps["thread-id"] != "m-1" || aps["category"] != "MONITOR_DOWN" {
		t.Fatalf("aps %v", aps)
	}

	// Expired token: fetched again.
	c.now = func() time.Time { return time.Now().Add(58 * time.Minute) }
	if err := c.Send(ctx, m); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Load() != 2 {
		t.Fatalf("%d token requests, want 2", f.tokens.Load())
	}
}

func TestSendErrors(t *testing.T) {
	cases := []struct {
		code  int
		reply string
		want  error
	}{
		{404, `{"error":{"status":"NOT_FOUND","message":"Requested entity was not found.","details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`, ErrUnregistered},
		{400, `{"error":{"status":"INVALID_ARGUMENT","message":"The registration token is not a valid FCM registration token"}}`, ErrInvalid},
		{400, `{"error":{"status":"INVALID_ARGUMENT","message":"Invalid Live Activity Token"}}`, ErrActivityToken},
		{400, `{"error":{"status":"INVALID_ARGUMENT","message":"Invalid Live Activity Token"}}`, ErrInvalid},
		{403, `{"error":{"status":"PERMISSION_DENIED","details":[{"errorCode":"SENDER_ID_MISMATCH"}]}}`, ErrUnregistered},
		{429, `{"error":{"status":"RESOURCE_EXHAUSTED","details":[{"errorCode":"QUOTA_EXCEEDED"}]}}`, ErrQuota},
	}
	for _, tc := range cases {
		f := newFake(t)
		f.sendReply = func(int32) (int, string) { return tc.code, tc.reply }
		err := f.client(t).Send(context.Background(), Message{Token: "x", Title: "t"})
		if !errors.Is(err, tc.want) {
			t.Fatalf("http %d: got %v, want %v", tc.code, err, tc.want)
		}
	}
	f := newFake(t)
	f.sendReply = func(int32) (int, string) { return 503, `{"error":{"status":"UNAVAILABLE"}}` }
	err := f.client(t).Send(context.Background(), Message{Token: "x"})
	if err == nil || errors.Is(err, ErrUnregistered) || errors.Is(err, ErrInvalid) {
		t.Fatalf("503: %v", err)
	}
}

func TestSendRetriesOn401(t *testing.T) {
	f := newFake(t)
	f.sendReply = func(n int32) (int, string) {
		if n == 1 {
			return 401, `{"error":{"status":"UNAUTHENTICATED"}}`
		}
		return 200, `{}`
	}
	if err := f.client(t).Send(context.Background(), Message{Token: "x"}); err != nil {
		t.Fatal(err)
	}
	if f.tokens.Load() != 2 {
		t.Fatalf("%d token requests, want 2", f.tokens.Load())
	}
}

func TestLiveActivityPayload(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	at := time.Unix(1_800_000_000, 0)
	start := Message{Token: "dev", Title: "2 monitors down", Body: "api, web", HighPrio: true, Silent: true,
		LiveActivity: &LiveActivity{
			Token: "abcd", Event: EventStart, ContentState: json.RawMessage(`{"count":2}`),
			AttributesType: "OutageActivityAttributes", Attributes: json.RawMessage(`{"hub":"https://h"}`),
			Timestamp: at, StaleDate: at.Add(30 * time.Minute),
		}}
	if err := c.Send(context.Background(), start); err != nil {
		t.Fatal(err)
	}
	msg := f.last.Load().(map[string]any)["message"].(map[string]any)
	if msg["token"] != "dev" || msg["notification"] != nil {
		t.Fatalf("message %v", msg)
	}
	apns := msg["apns"].(map[string]any)
	if apns["live_activity_token"] != "abcd" {
		t.Fatalf("apns %v", apns)
	}
	if h := apns["headers"].(map[string]any); h["apns-priority"] != "10" || h["apns-push-type"] != nil {
		t.Fatalf("headers %v", h)
	}
	aps := apns["payload"].(map[string]any)["aps"].(map[string]any)
	if aps["event"] != "start" || aps["timestamp"] != float64(at.Unix()) || aps["stale-date"] != float64(at.Unix()+1800) ||
		aps["attributes-type"] != "OutageActivityAttributes" || aps["attributes"].(map[string]any)["hub"] != "https://h" ||
		aps["content-state"].(map[string]any)["count"] != float64(2) || aps["sound"] != nil ||
		aps["alert"].(map[string]any)["title"] != "2 monitors down" || aps["dismissal-date"] != nil {
		t.Fatalf("aps %v", aps)
	}

	end := Message{Token: "dev", LiveActivity: &LiveActivity{Token: "abcd", Event: EventEnd,
		ContentState: json.RawMessage(`{"count":0}`), Attributes: json.RawMessage(`{"x":1}`), DismissalDate: at}}
	if err := c.Send(context.Background(), end); err != nil {
		t.Fatal(err)
	}
	apns = f.last.Load().(map[string]any)["message"].(map[string]any)["apns"].(map[string]any)
	aps = apns["payload"].(map[string]any)["aps"].(map[string]any)
	if aps["event"] != "end" || aps["dismissal-date"] != float64(at.Unix()) || aps["alert"] != nil ||
		aps["attributes"] != nil || aps["timestamp"] == nil || apns["headers"].(map[string]any)["apns-priority"] != "5" {
		t.Fatalf("end aps %v", apns)
	}
}
