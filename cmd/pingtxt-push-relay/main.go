// Command pingtxt-push-relay forwards notifications from self-hosted pingtxt
// hubs to the pingtxt iOS app through Firebase Cloud Messaging.
//
//	pingtxt-push-relay              run the server (settings from env, see README)
//	pingtxt-push-relay healthcheck  exit 0 if the local server answers /healthz
//	pingtxt-push-relay hub-token    print a new hub id and token (for closed relays)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/federico-it/pingtxt-push-relay/internal/config"
	"github.com/federico-it/pingtxt-push-relay/internal/fcm"
	"github.com/federico-it/pingtxt-push-relay/internal/keys"
	"github.com/federico-it/pingtxt-push-relay/internal/server"
)

var version = "dev"

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "":
		err = run()
	case "healthcheck":
		err = healthcheck()
	case "hub-token":
		err = hubToken()
	case "version", "-version", "--version":
		fmt.Println(version)
	default:
		err = fmt.Errorf("unknown command %q (use healthcheck, hub-token or version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingtxt-push-relay:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		return fmt.Errorf("RELAY_LOG_LEVEL=%q: use debug, info, warn or error", cfg.LogLevel)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	k, err := keys.New(cfg.Secret)
	if err != nil {
		return err
	}
	var sender server.Sender
	if cfg.FCMKey != nil {
		sa, err := fcm.ParseServiceAccount(cfg.FCMKey)
		if err != nil {
			return err
		}
		c, err := fcm.New(sa, fcm.Options{DryRun: cfg.FCMDryRun})
		if err != nil {
			return err
		}
		sender = c
		log.Info("fcm ready", "project", c.ProjectID(), "dry_run", cfg.FCMDryRun)
	} else {
		log.Warn("FCM_CREDENTIALS not set: pushes answer 503")
	}

	s := server.New(cfg, k, sender, log, version)
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.Sweep()
			}
		}
	}()

	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.Addr, "version", version, "registration", cfg.Registration)
		errc <- srv.ListenAndServe()
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shut, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := srv.Shutdown(shut); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// healthcheck is for the Docker HEALTHCHECK: the image has no shell or curl.
func healthcheck() error {
	addr := os.Getenv("RELAY_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: http %d", resp.StatusCode)
	}
	return nil
}

// hubToken prints credentials for a hub, for relays with
// RELAY_REGISTRATION=closed. Uses the same RELAY_SECRET as the server.
func hubToken() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	k, err := keys.New(cfg.Secret)
	if err != nil {
		return err
	}
	id, tok := k.NewHub()
	fmt.Printf("hub_id=%s\nhub_token=%s\n", id, strings.TrimSpace(tok))
	return nil
}
