// Package fcm sends messages with the Firebase Cloud Messaging HTTP v1 API,
// signed in with a Google service account. Only the standard library: the
// OAuth token is a JWT signed with the service account key, exchanged at
// Google's token endpoint and cached until shortly before it expires.
package fcm

import (
	"bytes"
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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	scope        = "https://www.googleapis.com/auth/firebase.messaging"
	defaultToken = "https://oauth2.googleapis.com/token"
	defaultAPI   = "https://fcm.googleapis.com"
)

// ServiceAccount is the part of the Firebase service account JSON key that
// the relay needs.
type ServiceAccount struct {
	Type        string `json:"type"`
	ProjectID   string `json:"project_id"`
	PrivateKey  string `json:"private_key"`
	ClientEmail string `json:"client_email"`
	TokenURI    string `json:"token_uri"`
}

// Message is one notification for one device.
type Message struct {
	Token      string
	Title      string
	Body       string
	Data       map[string]string
	ThreadID   string        // groups notifications on the phone
	CollapseID string        // a newer message replaces an older one
	Category   string        // aps.category: the app's UNNotificationCategory (action buttons)
	HighPrio   bool          // alert now (down), else let iOS choose
	TTL        time.Duration // 0 = FCM default (4 weeks)
	Silent     bool          // no sound

	// LiveActivity, when set, makes this an update of a Live Activity
	// instead of a notification. Token is still the FCM token of the phone.
	LiveActivity *LiveActivity
}

// Events of a Live Activity push.
const (
	EventStart  = "start"  // push-to-start token, iOS 17.2+
	EventUpdate = "update" // token of the running activity
	EventEnd    = "end"
)

// LiveActivity is an ActivityKit push sent through FCM
// (apns.live_activity_token). Title and Body of the Message, when set,
// become the alert that lights up the screen; without them the activity
// changes silently.
type LiveActivity struct {
	Token          string          // push token of the activity, or the push-to-start token
	Event          string          // EventStart, EventUpdate or EventEnd
	ContentState   json.RawMessage // the activity's ContentState as JSON
	AttributesType string          // start only: the ActivityAttributes type name
	Attributes     json.RawMessage // start only
	Timestamp      time.Time       // when the state was true; zero = now
	StaleDate      time.Time       // zero = none
	DismissalDate  time.Time       // end only; zero = iOS default (up to 4 hours)
	RelevanceScore float64         // 0 = none
}

// Result kinds of a send.
var (
	// ErrUnregistered: the token is no longer valid (app removed, signed
	// out, token rotated). The hub must forget the device.
	ErrUnregistered = errors.New("device unregistered")
	// ErrInvalid: FCM refused the message or the token.
	ErrInvalid = errors.New("invalid message")
	// ErrQuota: FCM rate limit, try later.
	ErrQuota = errors.New("fcm quota exceeded")
)

// Client sends messages. It is safe for concurrent use.
type Client struct {
	sa     ServiceAccount
	key    *rsa.PrivateKey
	http   *http.Client
	api    string
	dryRun bool

	mu      sync.Mutex
	token   string
	expires time.Time
	now     func() time.Time
}

// Options of a Client. Zero values are fine.
type Options struct {
	HTTPClient *http.Client
	APIBase    string // tests
	TokenURL   string // tests; default from the key, then Google's
	DryRun     bool   // FCM validates but does not deliver
}

// ParseServiceAccount reads a service account JSON key.
func ParseServiceAccount(data []byte) (ServiceAccount, error) {
	var sa ServiceAccount
	if err := json.Unmarshal(data, &sa); err != nil {
		return sa, fmt.Errorf("service account: %w", err)
	}
	if sa.Type != "service_account" || sa.ProjectID == "" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return sa, errors.New("service account: not a Firebase service account JSON key")
	}
	return sa, nil
}

// New makes a client for a service account.
func New(sa ServiceAccount, opt Options) (*Client, error) {
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("service account: private_key is not PEM")
	}
	var key *rsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("service account: private_key is not RSA")
		}
		key = rk
	} else if rk, err2 := x509.ParsePKCS1PrivateKey(block.Bytes); err2 == nil {
		key = rk
	} else {
		return nil, fmt.Errorf("service account: private_key: %w", err)
	}
	if opt.TokenURL != "" {
		sa.TokenURI = opt.TokenURL
	}
	if sa.TokenURI == "" {
		sa.TokenURI = defaultToken
	}
	c := &Client{sa: sa, key: key, http: opt.HTTPClient, api: opt.APIBase, dryRun: opt.DryRun, now: time.Now}
	if c.http == nil {
		c.http = &http.Client{Timeout: 15 * time.Second}
	}
	if c.api == "" {
		c.api = defaultAPI
	}
	return c, nil
}

// ProjectID is the Firebase project messages go to.
func (c *Client) ProjectID() string { return c.sa.ProjectID }

// accessToken returns a cached OAuth token, refreshing it 5 minutes before
// it expires.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.now().Before(c.expires.Add(-5*time.Minute)) {
		return c.token, nil
	}
	assertion, err := c.jwt()
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.sa.TokenURI, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oauth token: http %d: %s", resp.StatusCode, oneLine(body))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("oauth token: bad response")
	}
	if tr.ExpiresIn <= 0 {
		tr.ExpiresIn = 3600
	}
	c.token = tr.AccessToken
	c.expires = c.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}

func (c *Client) jwt() (string, error) {
	enc := base64.RawURLEncoding
	now := c.now().Unix()
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss":   c.sa.ClientEmail,
		"scope": scope,
		"aud":   c.sa.TokenURI,
		"iat":   now,
		"exp":   now + 3600,
	})
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// Send delivers one message. Errors wrap ErrUnregistered, ErrInvalid or
// ErrQuota when FCM says so; any other error is temporary.
func (c *Client) Send(ctx context.Context, m Message) error {
	body, err := json.Marshal(map[string]any{"message": c.payload(m), "validate_only": c.dryRun})
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		tok, err := c.accessToken(ctx)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.api+"/v1/projects/"+url.PathEscape(c.sa.ProjectID)+"/messages:send", bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return fmt.Errorf("fcm: %w", err)
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		// A token revoked early: drop it and try once more.
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
			continue
		}
		return classify(resp.StatusCode, rb)
	}
}

func (c *Client) payload(m Message) map[string]any {
	if m.LiveActivity != nil {
		return c.liveActivityPayload(m)
	}
	aps := map[string]any{
		"alert": map[string]string{"title": m.Title, "body": m.Body},
	}
	if !m.Silent {
		aps["sound"] = "default"
	}
	if m.ThreadID != "" {
		aps["thread-id"] = m.ThreadID
	}
	if m.Category != "" {
		aps["category"] = m.Category
	}
	headers := map[string]string{"apns-push-type": "alert", "apns-priority": "5"}
	if m.HighPrio {
		headers["apns-priority"] = "10"
		aps["interruption-level"] = "time-sensitive"
	}
	if m.CollapseID != "" {
		headers["apns-collapse-id"] = m.CollapseID
	}
	if m.TTL > 0 {
		headers["apns-expiration"] = strconv.FormatInt(c.now().Add(m.TTL).Unix(), 10)
	}
	msg := map[string]any{
		"token":        m.Token,
		"notification": map[string]string{"title": m.Title, "body": m.Body},
		"apns":         map[string]any{"headers": headers, "payload": map[string]any{"aps": aps}},
	}
	if len(m.Data) > 0 {
		msg["data"] = m.Data
	}
	return msg
}

// liveActivityPayload follows
// https://firebase.google.com/docs/cloud-messaging/customize-messages/live-activity
// FCM sets the APNs push type and topic itself when live_activity_token is
// there; only the priority is ours. No top-level notification: it would turn
// the message into a normal alert.
func (c *Client) liveActivityPayload(m Message) map[string]any {
	la := m.LiveActivity
	ts := la.Timestamp
	if ts.IsZero() {
		ts = c.now()
	}
	aps := map[string]any{
		"timestamp":     ts.Unix(),
		"event":         la.Event,
		"content-state": la.ContentState,
	}
	if !la.StaleDate.IsZero() {
		aps["stale-date"] = la.StaleDate.Unix()
	}
	if la.Event == EventEnd && !la.DismissalDate.IsZero() {
		aps["dismissal-date"] = la.DismissalDate.Unix()
	}
	if la.Event == EventStart {
		aps["attributes-type"] = la.AttributesType
		aps["attributes"] = la.Attributes
	}
	if la.RelevanceScore > 0 {
		aps["relevance-score"] = la.RelevanceScore
	}
	if m.Title != "" {
		alert := map[string]string{"title": m.Title}
		if m.Body != "" {
			alert["body"] = m.Body
		}
		aps["alert"] = alert
		if !m.Silent {
			aps["sound"] = "default"
		}
	}
	headers := map[string]string{"apns-priority": "5"}
	if m.HighPrio {
		headers["apns-priority"] = "10"
	}
	if m.TTL > 0 {
		headers["apns-expiration"] = strconv.FormatInt(c.now().Add(m.TTL).Unix(), 10)
	}
	return map[string]any{
		"token": m.Token,
		"apns": map[string]any{
			"live_activity_token": la.Token,
			"headers":             headers,
			"payload":             map[string]any{"aps": aps},
		},
	}
}

// classify maps an FCM error response to the errors of this package.
// https://firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
func classify(status int, body []byte) error {
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Details []struct {
				Type      string `json:"@type"`
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	json.Unmarshal(body, &e)
	code := e.Error.Status
	for _, d := range e.Error.Details {
		if d.ErrorCode != "" {
			code = d.ErrorCode
		}
	}
	msg := e.Error.Message
	if msg == "" {
		msg = http.StatusText(status)
	}
	switch {
	case code == "UNREGISTERED" || status == http.StatusNotFound:
		return fmt.Errorf("%w: %s", ErrUnregistered, msg)
	case code == "SENDER_ID_MISMATCH":
		// Token of another Firebase project: never deliverable here.
		return fmt.Errorf("%w: %s", ErrUnregistered, msg)
	case code == "QUOTA_EXCEEDED" || status == http.StatusTooManyRequests:
		return fmt.Errorf("%w: %s", ErrQuota, msg)
	case code == "INVALID_ARGUMENT" || status == http.StatusBadRequest:
		return fmt.Errorf("%w: %s", ErrInvalid, msg)
	default: // UNAVAILABLE, INTERNAL, THIRD_PARTY_AUTH_ERROR, 5xx
		return fmt.Errorf("fcm: http %d %s: %s", status, code, msg)
	}
}

func oneLine(b []byte) string {
	if len(b) > 300 {
		b = b[:300]
	}
	return string(bytes.ReplaceAll(b, []byte("\n"), []byte(" ")))
}
