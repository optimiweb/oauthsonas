package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/optimiweb/oauthsonas/internal/config"
	"golang.org/x/oauth2"
)

const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~abcdef"

type testProvider struct {
	baseURL  string
	server   *http.Server
	listener net.Listener
}

func newTestProvider(t *testing.T, codeTTL time.Duration) *testProvider {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	c := testConfig("http://" + listener.Addr().String())
	c.AuthorizationCodeTTL = codeTTL.String()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: s.Handler()}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return &testProvider{baseURL: c.Issuer, server: server, listener: listener}
}

func testConfig(issuer string) *config.Config {
	return &config.Config{
		Issuer: issuer, APIAudience: "https://api.optimicdn.test", TokenTTL: "15m", AuthorizationCodeTTL: "5m", RefreshTokenTTL: "8h",
		Clients: []config.Client{{ID: "dashboard", Name: "Dashboard", Public: true, RedirectURIs: []string{"http://127.0.0.1:5173/auth/callback"}, PostLogoutRedirectURIs: []string{"http://127.0.0.1:5173/"}, AllowedOrigins: []string{"http://127.0.0.1:5173"}}},
		Personas: []config.Persona{
			{ID: "acme-admin", Subject: "testoidc|acme-admin", Email: "admin@acme.dev.optimi.test", Name: "Acme Administrator", OrganizationID: "org_acme", Roles: []string{"customer-admin"}},
			{ID: "operator", Subject: "testoidc|operator", Email: "operator@dev.optimi.test", Name: "Operations User", Roles: []string{"operator"}},
		},
	}
}

func browserClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func challenge(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authorizeURL(base string, params url.Values) string {
	return base + "/oauth2/auth?" + params.Encode()
}

func validAuthorizeParams() url.Values {
	return url.Values{"response_type": {"code"}, "client_id": {"dashboard"}, "redirect_uri": {"http://127.0.0.1:5173/auth/callback"}, "scope": {"openid profile email"}, "state": {"state-value-123"}, "nonce": {"nonce-value-123"}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "audience": {"https://api.optimicdn.test"}}
}

func begin(t *testing.T, p *testProvider, client *http.Client, params url.Values) string {
	t.Helper()
	response, err := client.Get(authorizeURL(p.baseURL, params))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authorize status = %d", response.StatusCode)
	}
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "Acme Administrator") {
		t.Fatalf("chooser did not render: %s", body)
	}
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)
	if len(match) != 2 {
		t.Fatalf("csrf missing from chooser: %s", body)
	}
	return string(match[1])
}

func selectPersona(t *testing.T, p *testProvider, client *http.Client, csrf, persona string) string {
	t.Helper()
	response, err := client.PostForm(p.baseURL+"/oauth2/auth/select", url.Values{"csrf": {csrf}, "persona": {persona}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound && response.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("selection status = %d: %s", response.StatusCode, body)
	}
	location := response.Header.Get("Location")
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("state") != "state-value-123" {
		t.Fatalf("state = %q", u.Query().Get("state"))
	}
	if u.Query().Get("code") == "" {
		t.Fatalf("code absent from %s", location)
	}
	return u.Query().Get("code")
}

func exchange(t *testing.T, p *testProvider, client *http.Client, code, suppliedVerifier string) map[string]interface{} {
	t.Helper()
	response, err := client.PostForm(p.baseURL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "client_id": {"dashboard"}, "code": {code}, "redirect_uri": {"http://127.0.0.1:5173/auth/callback"}, "code_verifier": {suppliedVerifier}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]interface{}
	_ = json.NewDecoder(response.Body).Decode(&result)
	result["_status"] = response.StatusCode
	return result
}

func fullFlow(t *testing.T, p *testProvider, persona string) (*http.Client, map[string]interface{}) {
	t.Helper()
	client := browserClient(t)
	csrf := begin(t, p, client, validAuthorizeParams())
	code := selectPersona(t, p, client, csrf, persona)
	result := exchange(t, p, client, code, verifier)
	if result["_status"] != float64(http.StatusOK) && result["_status"] != http.StatusOK {
		t.Fatalf("token exchange: %#v", result)
	}
	return client, result
}

func jwtClaims(t *testing.T, p *testProvider, token string) map[string]interface{} {
	t.Helper()
	response, err := http.Get(p.baseURL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var keys jose.JSONWebKeySet
	if err := json.NewDecoder(response.Body).Decode(&keys); err != nil {
		t.Fatal(err)
	}
	signed, err := jose.ParseSigned(token)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := signed.Verify(keys.Keys[0].Key)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestDiscoveryAndFullAuthorizationCodeFlow(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	response, err := http.Get(p.baseURL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var discovery map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		t.Fatal(err)
	}
	if discovery["issuer"] != p.baseURL || discovery["jwks_uri"] != p.baseURL+"/.well-known/jwks.json" {
		t.Fatalf("bad discovery: %#v", discovery)
	}
	if !containsString(discovery["code_challenge_methods_supported"], "S256") {
		t.Fatal("discovery does not advertise S256")
	}

	client, result := fullFlow(t, p, "acme-admin")
	accessToken, idToken := result["access_token"].(string), result["id_token"].(string)
	access, id := jwtClaims(t, p, accessToken), jwtClaims(t, p, idToken)
	if access["iss"] != p.baseURL || access["sub"] != "testoidc|acme-admin" || access["client_id"] != "dashboard" || access["scope"] != "openid profile email" {
		t.Fatalf("bad access claims: %#v", access)
	}
	if _, ok := access["email"]; ok {
		t.Fatalf("access token must not contain profile claims: %#v", access)
	}
	if !containsString(access["aud"], "https://api.optimicdn.test") || !containsString(access[rolesClaim], "customer-admin") || access["org_id"] != "org_acme" {
		t.Fatalf("bad access claims: %#v", access)
	}
	if id["iss"] != p.baseURL || id["sub"] != "testoidc|acme-admin" || id["nonce"] != "nonce-value-123" || !containsString(id["aud"], "dashboard") {
		t.Fatalf("bad id claims: %#v", id)
	}
	if id["email"] != "admin@acme.dev.optimi.test" || id["name"] != "Acme Administrator" || !containsString(id[rolesClaim], "customer-admin") || id["org_id"] != "org_acme" {
		t.Fatalf("bad id claims: %#v", id)
	}

	request, _ := http.NewRequest(http.MethodGet, p.baseURL+"/userinfo", nil)
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status %d", response.StatusCode)
	}
	var userinfo map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&userinfo); err != nil {
		t.Fatal(err)
	}
	if userinfo["email"] != "admin@acme.dev.optimi.test" || userinfo["name"] != "Acme Administrator" || userinfo["org_id"] != "org_acme" {
		t.Fatalf("bad userinfo claims: %#v", userinfo)
	}
}

func TestStaffPersonaHasNoOrganization(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	_, result := fullFlow(t, p, "operator")
	claims := jwtClaims(t, p, result["access_token"].(string))
	if _, ok := claims["org_id"]; ok {
		t.Fatalf("staff token includes org_id: %#v", claims)
	}
}

func TestOAuth2ClientAuthorizationCodeFlow(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	browser := browserClient(t)
	oauthClient := &oauth2.Config{
		ClientID:    "dashboard",
		RedirectURL: "http://127.0.0.1:5173/auth/callback",
		Scopes:      []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.baseURL + "/oauth2/auth",
			TokenURL: p.baseURL + "/oauth2/token",
		},
	}

	authorizeURL := oauthClient.AuthCodeURL(
		"state-value-123",
		oauth2.S256ChallengeOption(verifier),
		oauth2.SetAuthURLParam("nonce", "nonce-value-123"),
		oauth2.SetAuthURLParam("audience", "https://api.optimicdn.test"),
	)
	u, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	csrf := begin(t, p, browser, u.Query())
	code := selectPersona(t, p, browser, csrf, "acme-admin")

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, browser)
	token, err := oauthClient.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("oauth2 exchange: %v", err)
	}
	if token.AccessToken == "" || token.Extra("id_token") == nil {
		t.Fatalf("oauth2 token is incomplete: %#v", token)
	}
	claims := jwtClaims(t, p, token.AccessToken)
	if claims["sub"] != "testoidc|acme-admin" || claims["org_id"] != "org_acme" {
		t.Fatalf("unexpected OAuth2 access token claims: %#v", claims)
	}

	response, err := oauthClient.Client(ctx, token).Get(p.baseURL + "/userinfo")
	if err != nil {
		t.Fatalf("oauth2 userinfo request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status = %d", response.StatusCode)
	}
	var userinfo map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&userinfo); err != nil {
		t.Fatal(err)
	}
	if userinfo["email"] != "admin@acme.dev.optimi.test" || userinfo[rolesClaim] == nil {
		t.Fatalf("unexpected OAuth2 userinfo: %#v", userinfo)
	}
}

func TestAuthorizationFailuresAndCodeReuse(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	cases := []struct {
		name   string
		mutate func(url.Values)
	}{
		{"missing PKCE", func(v url.Values) { v.Del("code_challenge") }},
		{"plain PKCE", func(v url.Values) { v.Set("code_challenge_method", "plain") }},
		{"unknown client", func(v url.Values) { v.Set("client_id", "unknown") }},
		{"bad redirect", func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:9999/callback") }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			params := validAuthorizeParams()
			test.mutate(params)
			response, err := client.Get(authorizeURL(p.baseURL, params))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode == http.StatusOK {
				t.Fatalf("invalid request rendered chooser")
			}
		})
	}
	csrf := begin(t, p, client, validAuthorizeParams())
	code := selectPersona(t, p, client, csrf, "acme-admin")
	wrong := exchange(t, p, client, code, verifier+"x")
	if wrong["_status"] != float64(http.StatusBadRequest) && wrong["_status"] != http.StatusBadRequest {
		t.Fatalf("wrong verifier accepted: %#v", wrong)
	}
	// PKCE request sessions are one-time too; issue a fresh code for reuse validation.
	csrf = begin(t, p, client, validAuthorizeParams())
	code = selectPersona(t, p, client, csrf, "acme-admin")
	first := exchange(t, p, client, code, verifier)
	if first["_status"] != float64(http.StatusOK) && first["_status"] != http.StatusOK {
		t.Fatalf("first exchange failed: %#v", first)
	}
	second := exchange(t, p, client, code, verifier)
	if second["_status"] != float64(http.StatusBadRequest) && second["_status"] != http.StatusBadRequest {
		t.Fatalf("reused code accepted: %#v", second)
	}
}

func TestExpiredCodeAndInteractionTampering(t *testing.T) {
	p := newTestProvider(t, 5*time.Millisecond)
	client := browserClient(t)
	csrf := begin(t, p, client, validAuthorizeParams())
	response, err := client.PostForm(p.baseURL+"/oauth2/auth/select", url.Values{"csrf": {"wrong"}, "persona": {"operator"}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("forged selection status %d", response.StatusCode)
	}
	response, err = client.PostForm(p.baseURL+"/oauth2/auth/select", url.Values{"csrf": {csrf}, "persona": {"not-a-persona"}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("modified persona status %d", response.StatusCode)
	}
	// Failed tampering submissions do not consume a valid interaction.
	code := selectPersona(t, p, client, csrf, "acme-admin")
	time.Sleep(20 * time.Millisecond)
	result := exchange(t, p, client, code, verifier)
	if result["_status"] != float64(http.StatusBadRequest) && result["_status"] != http.StatusBadRequest {
		t.Fatalf("expired code accepted: %#v", result)
	}
}

func TestCORSAndLogoutValidation(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	request, _ := http.NewRequest(http.MethodOptions, p.baseURL+"/oauth2/token", nil)
	request.Header.Set("Origin", "http://evil.example")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden || response.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("bad CORS response: %d %q", response.StatusCode, response.Header.Get("Access-Control-Allow-Origin"))
	}
	response, err = http.Get(p.baseURL + "/logout?client_id=dashboard&post_logout_redirect_uri=http://evil.example/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid logout redirect status %d", response.StatusCode)
	}
}

func TestOfflineAccessRefreshRotationAndReuseRejection(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	params := validAuthorizeParams()
	params.Set("scope", "openid profile email offline_access")
	csrf := begin(t, p, client, params)
	code := selectPersona(t, p, client, csrf, "acme-admin")
	initial := exchange(t, p, client, code, verifier)
	if initial["_status"] != http.StatusOK || initial["refresh_token"] == nil {
		t.Fatalf("offline_access did not issue refresh token: %#v", initial)
	}
	refresh := initial["refresh_token"].(string)
	response, err := client.PostForm(p.baseURL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"dashboard"}, "refresh_token": {refresh}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var rotated map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || rotated["refresh_token"] == refresh || rotated["id_token"] == nil {
		t.Fatalf("refresh did not rotate correctly: status=%d body=%#v", response.StatusCode, rotated)
	}
	response, err = client.PostForm(p.baseURL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"dashboard"}, "refresh_token": {refresh}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("reused refresh token status %d", response.StatusCode)
	}
}

func containsString(value interface{}, wanted string) bool {
	values, ok := value.([]interface{})
	if !ok {
		return false
	}
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
