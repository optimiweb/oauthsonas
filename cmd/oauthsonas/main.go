package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/optimiweb/oauthsonas/internal/config"
	"github.com/optimiweb/oauthsonas/internal/server"
)

func main() {
	configPath := flag.String("config", "config.example.yaml", "path to YAML configuration")
	listen := flag.String("listen", "127.0.0.1:8181", "listen address")
	checkConfig := flag.Bool("check-config", false, "validate configuration and exit")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatalf("unexpected positional arguments: %s", strings.Join(flag.Args(), " "))
	}
	c, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	if *checkConfig {
		log.Printf("configuration %s is valid", *configPath)
		return
	}
	if err := validateListenAddress(*listen); err != nil {
		log.Fatal(err)
	}
	s, err := server.New(c)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("DEVELOPMENT ONLY: serving OIDC issuer %s on http://%s", c.Issuer, *listen)
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func validateListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", address, err)
	}
	if os.Getenv("TESTOIDC_ALLOW_NON_LOOPBACK") == "true" {
		return nil
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if host == "localhost" || (ip != nil && ip.IsLoopback()) {
		return nil
	}
	return fmt.Errorf("refusing non-loopback listen address %q; set TESTOIDC_ALLOW_NON_LOOPBACK=true to acknowledge development-only exposure", address)
}
