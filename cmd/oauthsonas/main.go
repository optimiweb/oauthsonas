package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/optimiweb/oauthsonas/internal/config"
	"github.com/optimiweb/oauthsonas/internal/server"
)

var version = "devel"

func main() {
	configPath := flag.String("config", "config.example.yaml", "path to YAML configuration")
	listen := flag.String("listen", "127.0.0.1:8181", "listen address")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	showVersion := flag.Bool("version", false, "print version and exit")
	logFormat := flag.String("log-format", "json", "log format: text or json")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	level := parseLogLevel(*logLevel)
	var handler slog.Handler
	switch *logFormat {
	case "text":
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	default:
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	}
	logger := slog.New(handler)

	if flag.NArg() != 0 {
		logger.Error("unexpected positional arguments", "args", strings.Join(flag.Args(), " "))
		os.Exit(1)
	}
	if *showVersion {
		fmt.Println(version)
		return
	}
	c, err := config.Load(*configPath)
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	if *checkConfig {
		logger.Info("configuration is valid", "path", *configPath)
		return
	}
	if err := validateListenAddress(*listen); err != nil {
		logger.Error("invalid listen address", "error", err)
		os.Exit(1)
	}
	s, err := server.New(c, logger, version)
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	logger.Info("starting developer OIDC provider", "issuer", c.Issuer, "listen", *listen)
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(listener) }()
	select {
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Error("serve failed", "error", err)
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func validateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	if os.Getenv("OAUTHSONAS_ALLOW_NON_LOOPBACK") == "true" {
		return nil
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing non-loopback listen address %q; set OAUTHSONAS_ALLOW_NON_LOOPBACK=true to acknowledge development-only exposure", address)
}
