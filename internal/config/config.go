package config

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the complete development OIDC server configuration.
type Config struct {
	Issuer                  string        `yaml:"issuer"`
	APIAudience             string        `yaml:"api_audience"`
	TokenTTL                string        `yaml:"token_ttl"`
	AuthorizationCodeTTL    string        `yaml:"authorization_code_ttl"`
	RefreshTokenTTL         string        `yaml:"refresh_token_ttl"`
	AllowedRoles            []string      `yaml:"allowed_roles"`
	Clients                 []Client      `yaml:"clients"`
	Personas                []Persona     `yaml:"personas"`
	TokenTTLDuration        time.Duration `yaml:"-"`
	AuthorizationCodeTTLD   time.Duration `yaml:"-"`
	RefreshTokenTTLDuration time.Duration `yaml:"-"`
}

type Client struct {
	ID                     string   `yaml:"id"`
	Name                   string   `yaml:"name"`
	Public                 bool     `yaml:"public"`
	RedirectURIs           []string `yaml:"redirect_uris"`
	PostLogoutRedirectURIs []string `yaml:"post_logout_redirect_uris"`
	AllowedOrigins         []string `yaml:"allowed_origins"`
}

type Persona struct {
	ID             string   `yaml:"id"`
	Subject        string   `yaml:"subject"`
	Email          string   `yaml:"email"`
	Name           string   `yaml:"name"`
	Roles          []string `yaml:"roles"`
	OrganizationID string   `yaml:"organization_id"`
	Memberships    []string `yaml:"memberships"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(b)))
	decoder.KnownFields(true)
	var c Config
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("config must contain exactly one YAML document")
		}
		return nil, fmt.Errorf("decode config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if err := validateAbsoluteURL(c.Issuer, "issuer"); err != nil {
		return err
	}
	issuer, _ := url.Parse(c.Issuer)
	if issuer.Path != "" {
		return fmt.Errorf("issuer must not include a path")
	}
	if strings.HasSuffix(c.Issuer, "/") {
		return fmt.Errorf("issuer must not end with '/'")
	}
	if strings.TrimSpace(c.APIAudience) == "" {
		return fmt.Errorf("api_audience is required")
	}
	if err := validateAbsoluteURL(c.APIAudience, "api_audience"); err != nil {
		return err
	}
	var err error
	if c.TokenTTLDuration, err = parseDuration(c.TokenTTL, "token_ttl", 15*time.Minute); err != nil {
		return err
	}
	if c.AuthorizationCodeTTLD, err = parseDuration(c.AuthorizationCodeTTL, "authorization_code_ttl", 5*time.Minute); err != nil {
		return err
	}
	if c.RefreshTokenTTLDuration, err = parseDuration(c.RefreshTokenTTL, "refresh_token_ttl", 8*time.Hour); err != nil {
		return err
	}
	if len(c.Clients) == 0 {
		return fmt.Errorf("at least one client is required")
	}
	if len(c.Personas) == 0 {
		return fmt.Errorf("at least one persona is required")
	}
	clientIDs := map[string]bool{}
	for i := range c.Clients {
		client := &c.Clients[i]
		if client.ID == "" || client.Name == "" {
			return fmt.Errorf("client %d requires id and name", i)
		}
		if clientIDs[client.ID] {
			return fmt.Errorf("duplicate client id %q", client.ID)
		}
		clientIDs[client.ID] = true
		if !client.Public {
			return fmt.Errorf("client %q must set public: true; confidential clients are unsupported", client.ID)
		}
		if len(client.RedirectURIs) == 0 {
			return fmt.Errorf("client %q requires at least one redirect_uri", client.ID)
		}
		for _, raw := range client.RedirectURIs {
			if err := validateRedirectURL(raw, "redirect_uri", client.ID); err != nil {
				return err
			}
		}
		for _, raw := range client.PostLogoutRedirectURIs {
			if err := validateRedirectURL(raw, "post_logout_redirect_uri", client.ID); err != nil {
				return err
			}
		}
		for _, raw := range client.AllowedOrigins {
			if err := validateOrigin(raw, client.ID); err != nil {
				return err
			}
		}
	}
	allowedRoles := map[string]bool{}
	for _, role := range c.AllowedRoles {
		if role == "" {
			return fmt.Errorf("allowed_roles must not contain an empty role")
		}
		if allowedRoles[role] {
			return fmt.Errorf("duplicate allowed role %q", role)
		}
		allowedRoles[role] = true
	}
	personaIDs, subjects := map[string]bool{}, map[string]bool{}
	for i := range c.Personas {
		p := &c.Personas[i]
		if p.ID == "" || p.Subject == "" || p.Email == "" || p.Name == "" {
			return fmt.Errorf("persona %d requires id, subject, email, and name", i)
		}
		if personaIDs[p.ID] {
			return fmt.Errorf("duplicate persona id %q", p.ID)
		}
		if subjects[p.Subject] {
			return fmt.Errorf("duplicate persona subject %q", p.Subject)
		}
		personaIDs[p.ID], subjects[p.Subject] = true, true
		if len(p.Roles) == 0 {
			return fmt.Errorf("persona %q requires at least one role", p.ID)
		}
		for _, role := range p.Roles {
			if role == "" {
				return fmt.Errorf("persona %q has an empty role", p.ID)
			}
			if len(allowedRoles) != 0 && !allowedRoles[role] {
				return fmt.Errorf("persona %q has unsupported role %q", p.ID, role)
			}
		}
	}
	return nil
}

func parseDuration(raw, field string, fallback time.Duration) (time.Duration, error) {
	if raw == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive Go duration", field)
	}
	return d, nil
}

func validateAbsoluteURL(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fmt.Errorf("%s must be an absolute http(s) URL without query or fragment", field)
	}
	return nil
}

func validateRedirectURL(raw, field, client string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Fragment != "" {
		return fmt.Errorf("client %q: %s must be an absolute http(s) URL without fragment", client, field)
	}
	return nil
}

func validateOrigin(raw, client string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("client %q: allowed_origin %q must be a scheme and host only", client, raw)
	}
	return nil
}
