package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := `issuer: http://127.0.0.1:8181
api_audience: https://api.example.test
clients:
  - id: dashboard
    name: Dashboard
    public: true
    redirect_uris: [http://127.0.0.1:5173/callback]
    typo_origin: http://127.0.0.1:5173
personas:
  - id: user
    subject: testoidc|user
    email: user@example.test
    name: User
    roles: [viewer]
`
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "typo_origin") {
		t.Fatalf("unknown field accepted: %v", err)
	}
}

func TestValidateRejectsDuplicateIDsAndInvalidIssuer(t *testing.T) {
	c := &Config{
		Issuer: "not-a-url", APIAudience: "https://api.example.test",
		Clients:  []Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/callback"}}},
		Personas: []Persona{{ID: "one", Subject: "subject", Email: "one@example.test", Name: "One", Roles: []string{"viewer"}}, {ID: "one", Subject: "subject-two", Email: "two@example.test", Name: "Two", Roles: []string{"viewer"}}},
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("invalid issuer accepted: %v", err)
	}
	c.Issuer = "http://127.0.0.1:8181"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate persona id") {
		t.Fatalf("duplicate persona accepted: %v", err)
	}
}
