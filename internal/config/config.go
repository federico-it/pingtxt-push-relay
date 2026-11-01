// Package config reads the relay settings from environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Registration modes for new hubs.
const (
	RegOpen   = "open"   // any hub can register (public relay)
	RegToken  = "token"  // only with RELAY_REGISTRATION_TOKEN
	RegClosed = "closed" // no new hubs; tokens made with the CLI still work
)

type Config struct {
	Addr         string
	Secret       []byte
	FCMKey       []byte // service account JSON, nil = pushes answer 503
	FCMDryRun    bool
	Registration string
	RegToken     string
	RevokedHubs  map[string]bool
	TrustProxy   bool
	// ClientIPHeader names a header that holds the client IP, set by a CDN
	// in front (CF-Connecting-IP for Cloudflare). Empty = not used.
	ClientIPHeader string
	HubRate        int // pushes per hub per minute
	DeviceRate     int // pushes per device per minute
	IPRate         int // hub registrations + device enrollments per IP per minute
	LogLevel       string
}

// Load reads the environment. getenv is os.Getenv outside tests.
func Load(getenv func(string) string) (*Config, error) {
	c := &Config{
		Addr:         or(getenv("RELAY_ADDR"), ":8080"),
		Registration: or(getenv("RELAY_REGISTRATION"), RegOpen),
		RegToken:     getenv("RELAY_REGISTRATION_TOKEN"),
		RevokedHubs:  map[string]bool{},
		LogLevel:     or(getenv("RELAY_LOG_LEVEL"), "info"),

		ClientIPHeader: strings.TrimSpace(getenv("RELAY_CLIENT_IP_HEADER")),
	}
	var err error

	secret, err := valueOrFile(getenv, "RELAY_SECRET")
	if err != nil {
		return nil, err
	}
	secret = strings.TrimSpace(secret)
	if len(secret) < 32 {
		return nil, errors.New("RELAY_SECRET (or RELAY_SECRET_FILE) must be at least 32 characters; make one with: openssl rand -base64 48")
	}
	c.Secret = []byte(secret)

	key, err := valueOrFile(getenv, "FCM_CREDENTIALS")
	if err != nil {
		return nil, err
	}
	key = strings.TrimSpace(key)
	if key != "" && !strings.HasPrefix(key, "{") {
		// Base64 of the JSON, handy for env vars in a panel.
		b, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			return nil, errors.New("FCM_CREDENTIALS must be the service account JSON or its base64")
		}
		key = string(b)
	}
	if key != "" {
		c.FCMKey = []byte(key)
	}

	switch c.Registration {
	case RegOpen, RegClosed:
	case RegToken:
		if len(c.RegToken) < 16 {
			return nil, errors.New("RELAY_REGISTRATION=token needs RELAY_REGISTRATION_TOKEN (16+ characters)")
		}
	default:
		return nil, fmt.Errorf("RELAY_REGISTRATION=%q: use open, token or closed", c.Registration)
	}

	for _, h := range strings.Split(getenv("RELAY_REVOKED_HUBS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			c.RevokedHubs[h] = true
		}
	}
	if c.FCMDryRun, err = boolEnv(getenv, "FCM_DRY_RUN"); err != nil {
		return nil, err
	}
	if c.TrustProxy, err = boolEnv(getenv, "RELAY_TRUST_PROXY"); err != nil {
		return nil, err
	}
	if c.HubRate, err = intEnv(getenv, "RELAY_HUB_RATE", 120); err != nil {
		return nil, err
	}
	if c.DeviceRate, err = intEnv(getenv, "RELAY_DEVICE_RATE", 30); err != nil {
		return nil, err
	}
	if c.IPRate, err = intEnv(getenv, "RELAY_IP_RATE", 20); err != nil {
		return nil, err
	}
	return c, nil
}

// valueOrFile reads NAME, or the file named by NAME_FILE (Docker secrets).
func valueOrFile(getenv func(string) string, name string) (string, error) {
	if v := getenv(name); v != "" {
		return v, nil
	}
	path := getenv(name + "_FILE")
	if path == "" {
		return "", nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s_FILE: %w", name, err)
	}
	return string(b), nil
}

func boolEnv(getenv func(string) string, name string) (bool, error) {
	v := getenv(name)
	if v == "" {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s=%q: use true or false", name, v)
	}
	return b, nil
}

func intEnv(getenv func(string) string, name string, def int) (int, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s=%q: use a number, 0 turns the limit off", name, v)
	}
	return n, nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
