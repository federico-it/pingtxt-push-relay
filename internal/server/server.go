// Package server is the HTTP API of the relay. See docs/API.md.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/federico-it/pingtxt-push-relay/internal/config"
	"github.com/federico-it/pingtxt-push-relay/internal/fcm"
	"github.com/federico-it/pingtxt-push-relay/internal/keys"
	"github.com/federico-it/pingtxt-push-relay/internal/ratelimit"
)

// Sender delivers one message (fcm.Client, or a fake in tests).
type Sender interface {
	Send(ctx context.Context, m fcm.Message) error
}

type Server struct {
	cfg     *config.Config
	keys    *keys.Keys
	sender  Sender // nil when FCM is not configured
	log     *slog.Logger
	version string

	hubLimit    *ratelimit.Limiter
	deviceLimit *ratelimit.Limiter
	ipLimit     *ratelimit.Limiter
}

func New(cfg *config.Config, k *keys.Keys, sender Sender, log *slog.Logger, version string) *Server {
	return &Server{
		cfg: cfg, keys: k, sender: sender, log: log, version: version,
		hubLimit:    ratelimit.New(cfg.HubRate, max(cfg.HubRate, maxDevices)),
		deviceLimit: ratelimit.New(cfg.DeviceRate, max(cfg.DeviceRate/3, 5)),
		ipLimit:     ratelimit.New(cfg.IPRate, max(cfg.IPRate/2, 5)),
	}
}

// Sweep frees idle rate limit buckets; call it every minute or so.
func (s *Server) Sweep() {
	s.hubLimit.Sweep()
	s.deviceLimit.Sweep()
	s.ipLimit.Sweep()
}

const maxBody = 64 << 10

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /v1/hubs", s.registerHub)
	mux.HandleFunc("GET /v1/hubs/me", s.hubMe)
	mux.HandleFunc("POST /v1/devices", s.enrollDevice)
	mux.HandleFunc("POST /v1/push", s.push)
	return s.logRequests(mux)
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"name": "pingtxt-push-relay", "version": s.version})
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "fcm": s.sender != nil})
}

// POST /v1/hubs: a hub gets its id and token.
func (s *Server) registerHub(w http.ResponseWriter, r *http.Request) {
	switch s.cfg.Registration {
	case config.RegClosed:
		writeError(w, http.StatusForbidden, "registration_closed", "this relay does not accept new hubs")
		return
	case config.RegToken:
		tok, _ := bearer(r)
		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.cfg.RegToken)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized", "registration token required")
			return
		}
	}
	if !s.ipLimit.Allow("ip:"+s.clientIP(r), 1) {
		tooMany(w, 60)
		return
	}
	id, tok := s.keys.NewHub()
	s.log.Info("hub registered", "hub", id)
	writeJSON(w, http.StatusCreated, map[string]string{"hub_id": id, "hub_token": tok})
}

// GET /v1/hubs/me: lets a hub check its token ("test connection").
func (s *Server) hubMe(w http.ResponseWriter, r *http.Request) {
	hub, ok := s.authHub(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"hub_id": hub, "fcm": s.sender != nil})
}

// POST /v1/devices: the app turns its FCM token into a handle for one hub.
func (s *Server) enrollDevice(w http.ResponseWriter, r *http.Request) {
	if !s.ipLimit.Allow("ip:"+s.clientIP(r), 1) {
		tooMany(w, 60)
		return
	}
	var req struct {
		HubID    string `json:"hub_id"`
		FCMToken string `json:"fcm_token"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	if keys.ValidHubID(req.HubID) != nil {
		writeError(w, http.StatusBadRequest, "invalid_hub", "hub_id is not valid")
		return
	}
	if s.cfg.RevokedHubs[req.HubID] {
		writeError(w, http.StatusForbidden, "hub_revoked", "this hub is blocked on this relay")
		return
	}
	handle, err := s.keys.SealDevice(req.HubID, req.FCMToken)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_token", "fcm_token is missing or too long")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"device": handle})
}

// Limits of a push request. FCM allows 4 KB per message in total.
const (
	maxDevices  = 100
	maxTitle    = 200
	maxText     = 2000
	maxDataKeys = 16
	maxDataSize = 2048
	maxID       = 64
	maxTTL      = 28 * 24 * 3600
	workers     = 8
)

type pushRequest struct {
	Devices    []string          `json:"devices"`
	Title      string            `json:"title"`
	Body       string            `json:"body"`
	Data       map[string]string `json:"data"`
	ThreadID   string            `json:"thread_id"`
	CollapseID string            `json:"collapse_id"`
	Priority   string            `json:"priority"`
	TTL        int               `json:"ttl"`
	Silent     bool              `json:"silent"`
}

// Per-device result statuses.
const (
	StatusSent        = "sent"
	StatusGone        = "gone"         // delete the device: the app enrolls again
	StatusRateLimited = "rate_limited" // too many pushes to this phone
	StatusRejected    = "rejected"     // FCM refused the message
	StatusFailed      = "failed"       // temporary, can be retried
)

type pushResult struct {
	Device string `json:"device"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// POST /v1/push: a hub sends one notification to some of its devices.
func (s *Server) push(w http.ResponseWriter, r *http.Request) {
	hub, ok := s.authHub(w, r)
	if !ok {
		return
	}
	if s.sender == nil {
		writeError(w, http.StatusServiceUnavailable, "fcm_not_configured", "the relay has no Firebase credentials")
		return
	}
	var req pushRequest
	if !readJSON(w, r, &req) {
		return
	}
	if msg := validate(&req); msg != "" {
		writeError(w, http.StatusBadRequest, "invalid_request", msg)
		return
	}
	if !s.hubLimit.Allow("hub:"+hub, len(req.Devices)) {
		tooMany(w, 30)
		return
	}

	results := make([]pushResult, len(req.Devices))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range min(workers, len(req.Devices)) {
		wg.Go(func() {
			for i := range jobs {
				results[i] = s.sendOne(r.Context(), hub, req.Devices[i], &req)
			}
		})
	}
	for i := range req.Devices {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	counts := map[string]int{}
	for _, res := range results {
		counts[res.Status]++
	}
	s.log.Info("push", "hub", hub, "devices", len(results), "sent", counts[StatusSent],
		"gone", counts[StatusGone], "failed", counts[StatusFailed]+counts[StatusRejected], "limited", counts[StatusRateLimited])
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (s *Server) sendOne(ctx context.Context, hub, handle string, req *pushRequest) pushResult {
	res := pushResult{Device: handle}
	token, err := s.keys.OpenDevice(hub, handle)
	if err != nil {
		res.Status, res.Error = StatusGone, "device handle not valid for this hub"
		return res
	}
	sum := sha256.Sum256([]byte(token))
	if !s.deviceLimit.Allow("dev:"+hex.EncodeToString(sum[:12]), 1) {
		res.Status = StatusRateLimited
		return res
	}
	err = s.sender.Send(ctx, fcm.Message{
		Token: token, Title: req.Title, Body: req.Body, Data: req.Data,
		ThreadID: req.ThreadID, CollapseID: req.CollapseID,
		HighPrio: req.Priority == "high", TTL: time.Duration(req.TTL) * time.Second, Silent: req.Silent,
	})
	switch {
	case err == nil:
		res.Status = StatusSent
	case errors.Is(err, fcm.ErrUnregistered):
		res.Status, res.Error = StatusGone, "device no longer registered"
	case errors.Is(err, fcm.ErrInvalid):
		res.Status, res.Error = StatusRejected, "message refused by FCM"
		s.log.Warn("fcm refused message", "hub", hub, "err", err)
	case errors.Is(err, fcm.ErrQuota):
		res.Status, res.Error = StatusFailed, "FCM quota exceeded"
	default:
		res.Status, res.Error = StatusFailed, "FCM unavailable"
		s.log.Warn("fcm send failed", "hub", hub, "err", err)
	}
	return res
}

// reservedData are data keys FCM refuses.
func reservedData(k string) bool {
	l := strings.ToLower(k)
	return l == "from" || l == "message_type" || l == "notification" ||
		strings.HasPrefix(l, "google") || strings.HasPrefix(l, "gcm")
}

func validate(req *pushRequest) string {
	if len(req.Devices) == 0 || len(req.Devices) > maxDevices {
		return "devices: 1 to 100 handles"
	}
	seen := make(map[string]bool, len(req.Devices))
	for _, d := range req.Devices {
		if seen[d] {
			return "devices: duplicate handle"
		}
		seen[d] = true
	}
	if strings.TrimSpace(req.Title) == "" || len(req.Title) > maxTitle {
		return "title: required, at most 200 bytes"
	}
	if len(req.Body) > maxText {
		return "body: at most 2000 bytes"
	}
	if len(req.Data) > maxDataKeys {
		return "data: at most 16 keys"
	}
	size := 0
	for k, v := range req.Data {
		if k == "" || reservedData(k) {
			return "data: key " + strconv.Quote(k) + " is reserved"
		}
		size += len(k) + len(v)
	}
	if size > maxDataSize {
		return "data: at most 2048 bytes"
	}
	if len(req.ThreadID) > maxID || len(req.CollapseID) > maxID {
		return "thread_id, collapse_id: at most 64 bytes"
	}
	switch req.Priority {
	case "":
		req.Priority = "normal"
	case "high", "normal":
	default:
		return "priority: high or normal"
	}
	if req.TTL < 0 || req.TTL > maxTTL {
		return "ttl: 0 to 2419200 seconds"
	}
	return ""
}

func (s *Server) authHub(w http.ResponseWriter, r *http.Request) (string, bool) {
	tok, ok := bearer(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", "missing hub token")
		return "", false
	}
	hub, err := s.keys.CheckHubToken(tok)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid hub token")
		return "", false
	}
	if s.cfg.RevokedHubs[hub] {
		writeError(w, http.StatusForbidden, "hub_revoked", "this hub is blocked on this relay")
		return "", false
	}
	return hub, true
}

func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:]), true
	}
	return "", false
}

// clientIP is the peer address, or with RELAY_TRUST_PROXY the address the
// proxy in front (Traefik, Caddy, nginx) appended last to X-Forwarded-For.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "too_large", "body over 64 KB")
		} else {
			writeError(w, http.StatusBadRequest, "invalid_json", "body is not valid JSON")
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, kind, msg string) {
	writeJSON(w, code, map[string]string{"error": kind, "message": msg})
}

func tooMany(w http.ResponseWriter, retryAfter int) {
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeError(w, http.StatusTooManyRequests, "rate_limited", "too many requests, slow down")
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

// logRequests logs method, path, status and time. Never bodies, tokens or
// addresses: the relay keeps nothing about monitors or people.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, code: http.StatusOK}
		next.ServeHTTP(sw, r)
		if r.URL.Path == "/healthz" && sw.code == http.StatusOK {
			return
		}
		s.log.Debug("request", "method", r.Method, "path", r.URL.Path, "status", sw.code, "ms", time.Since(start).Milliseconds())
	})
}
