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
	"sync"
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

type testInteraction struct {
	csrf string
	id   string
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
			{ID: "acme-admin", Subject: "oauthsonas|acme-admin", Email: "admin@acme.dev.optimi.test", Name: "Acme Administrator", OrganizationID: "org_acme", Roles: []string{"customer-admin"}},
			{ID: "operator", Subject: "oauthsonas|operator", Email: "operator@dev.optimi.test", Name: "Operations User", Roles: []string{"operator"}},
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

func begin(t *testing.T, p *testProvider, client *http.Client, params url.Values) testInteraction {
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
	id := regexp.MustCompile(`name="interaction_id" value="([^"]+)"`).FindSubmatch(body)
	if len(id) != 2 {
		t.Fatalf("interaction id missing from chooser: %s", body)
	}
	return testInteraction{csrf: string(match[1]), id: string(id[1])}
}

func selectPersona(t *testing.T, p *testProvider, client *http.Client, interaction testInteraction, persona string) string {
	t.Helper()
	response, err := client.PostForm(p.baseURL+"/oauth2/auth/select", url.Values{"csrf": {interaction.csrf}, "interaction_id": {interaction.id}, "persona": {persona}})
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
	interaction := begin(t, p, client, validAuthorizeParams())
	code := selectPersona(t, p, client, interaction, persona)
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
	if !containsString(discovery["response_modes_supported"], "query") || discovery["request_uri_parameter_supported"] != false {
		t.Fatalf("bad discovery capabilities: %#v", discovery)
	}
	if discoveryResponseCache := response.Header.Get("Cache-Control"); discoveryResponseCache != "public, max-age=60" {
		t.Fatalf("discovery cache control = %q", discoveryResponseCache)
	}
	if discoveryResponseVary := response.Header.Get("Vary"); discoveryResponseVary != "Origin" {
		t.Fatalf("discovery vary = %q", discoveryResponseVary)
	}

	client, result := fullFlow(t, p, "acme-admin")
	accessToken, idToken := result["access_token"].(string), result["id_token"].(string)
	access, id := jwtClaims(t, p, accessToken), jwtClaims(t, p, idToken)
	if access["iss"] != p.baseURL || access["sub"] != "oauthsonas|acme-admin" || access["client_id"] != "dashboard" || access["scope"] != "openid profile email" {
		t.Fatalf("bad access claims: %#v", access)
	}
	if _, ok := access["email"]; ok {
		t.Fatalf("access token must not contain profile claims: %#v", access)
	}
	if !containsString(access["aud"], "https://api.optimicdn.test") || !containsString(access["roles"], "customer-admin") || access["org_id"] != "org_acme" {
		t.Fatalf("bad access claims: %#v", access)
	}
	if id["iss"] != p.baseURL || id["sub"] != "oauthsonas|acme-admin" || id["nonce"] != "nonce-value-123" || !containsString(id["aud"], "dashboard") {
		t.Fatalf("bad id claims: %#v", id)
	}
	if id["email"] != "admin@acme.dev.optimi.test" || id["name"] != "Acme Administrator" || !containsString(id["roles"], "customer-admin") || id["org_id"] != "org_acme" {
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

	response, err = http.Get(p.baseURL + "/userinfo?access_token=" + url.QueryEscape(accessToken))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("query access token status = %d", response.StatusCode)
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
	interaction := begin(t, p, browser, u.Query())
	code := selectPersona(t, p, browser, interaction, "acme-admin")

	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, browser)
	token, err := oauthClient.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		t.Fatalf("oauth2 exchange: %v", err)
	}
	if token.AccessToken == "" || token.Extra("id_token") == nil {
		t.Fatalf("oauth2 token is incomplete: %#v", token)
	}
	claims := jwtClaims(t, p, token.AccessToken)
	if claims["sub"] != "oauthsonas|acme-admin" || claims["org_id"] != "org_acme" {
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
	if userinfo["email"] != "admin@acme.dev.optimi.test" || userinfo["roles"] == nil {
		t.Fatalf("unexpected OAuth2 userinfo: %#v", userinfo)
	}
}

func TestPublicClientRejectsSecretAuthentication(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	interaction := begin(t, p, client, validAuthorizeParams())
	code := selectPersona(t, p, client, interaction, "acme-admin")

	request, err := http.NewRequest(http.MethodPost, p.baseURL+"/oauth2/token", strings.NewReader(url.Values{"grant_type": {"authorization_code"}, "client_id": {"dashboard"}, "code": {code}, "redirect_uri": {"http://127.0.0.1:5173/auth/callback"}, "code_verifier": {verifier}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("dashboard", "not-a-secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("public client accepted basic authentication: %d", response.StatusCode)
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
		{"different loopback port", func(v url.Values) { v.Set("redirect_uri", "http://127.0.0.1:9999/auth/callback") }},
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
	interaction := begin(t, p, client, validAuthorizeParams())
	code := selectPersona(t, p, client, interaction, "acme-admin")
	wrong := exchange(t, p, client, code, verifier+"x")
	if wrong["_status"] != float64(http.StatusBadRequest) && wrong["_status"] != http.StatusBadRequest {
		t.Fatalf("wrong verifier accepted: %#v", wrong)
	}
	// PKCE request sessions are one-time too; issue a fresh code for reuse validation.
	interaction = begin(t, p, client, validAuthorizeParams())
	code = selectPersona(t, p, client, interaction, "acme-admin")
	first := exchange(t, p, client, code, verifier)
	if first["_status"] != float64(http.StatusOK) && first["_status"] != http.StatusOK {
		t.Fatalf("first exchange failed: %#v", first)
	}
	second := exchange(t, p, client, code, verifier)
	if second["_status"] != float64(http.StatusBadRequest) && second["_status"] != http.StatusBadRequest {
		t.Fatalf("reused code accepted: %#v", second)
	}
}

func TestExplicitQueryResponseMode(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	params := validAuthorizeParams()
	params.Set("response_mode", "query")
	interaction := begin(t, p, client, params)
	if code := selectPersona(t, p, client, interaction, "acme-admin"); code == "" {
		t.Fatal("query response mode did not produce a code")
	}
}

func TestParallelBrowserInteractions(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	first := begin(t, p, client, validAuthorizeParams())
	second := begin(t, p, client, validAuthorizeParams())
	if code := selectPersona(t, p, client, first, "acme-admin"); code == "" {
		t.Fatal("first interaction did not produce a code")
	}
	if code := selectPersona(t, p, client, second, "operator"); code == "" {
		t.Fatal("second interaction did not produce a code")
	}
}

func TestExpiredCodeAndInteractionTampering(t *testing.T) {
	p := newTestProvider(t, 5*time.Millisecond)
	client := browserClient(t)
	interaction := begin(t, p, client, validAuthorizeParams())
	response, err := client.PostForm(p.baseURL+"/oauth2/auth/select", url.Values{"csrf": {"wrong"}, "interaction_id": {interaction.id}, "persona": {"operator"}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("forged selection status %d", response.StatusCode)
	}
	response, err = client.PostForm(p.baseURL+"/oauth2/auth/select", url.Values{"csrf": {interaction.csrf}, "interaction_id": {interaction.id}, "persona": {"not-a-persona"}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("modified persona status %d", response.StatusCode)
	}
	// Failed tampering submissions do not consume a valid interaction.
	code := selectPersona(t, p, client, interaction, "acme-admin")
	time.Sleep(20 * time.Millisecond)
	result := exchange(t, p, client, code, verifier)
	if result["_status"] != float64(http.StatusBadRequest) && result["_status"] != http.StatusBadRequest {
		t.Fatalf("expired code accepted: %#v", result)
	}
}

func TestCORSAndLogoutValidation(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	request, _ := http.NewRequest(http.MethodOptions, p.baseURL+"/.well-known/openid-configuration", nil)
	request.Header.Set("Origin", "http://127.0.0.1:5173")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent || response.Header.Get("Access-Control-Allow-Origin") != "http://127.0.0.1:5173" {
		t.Fatalf("discovery preflight: status=%d origin=%q", response.StatusCode, response.Header.Get("Access-Control-Allow-Origin"))
	}
	request, _ = http.NewRequest(http.MethodOptions, p.baseURL+"/oauth2/token", nil)
	request.Header.Set("Origin", "http://evil.example")
	response, err = http.DefaultClient.Do(request)
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
	client := browserClient(t)
	request, _ = http.NewRequest(http.MethodGet, p.baseURL+"/logout?client_id=dashboard&post_logout_redirect_uri="+url.QueryEscape("http://127.0.0.1:5173/")+"&state=logout-state", nil)
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || !strings.Contains(response.Header.Get("Location"), "state=logout-state") {
		t.Fatalf("logout did not preserve state: status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
}

func TestPersonaPickerSecurityHeaders(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	response, err := client.Get(authorizeURL(p.baseURL, validAuthorizeParams()))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	for header, want := range map[string]string{
		"Cache-Control":           "no-store",
		"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action " + p.baseURL + "; base-uri 'none'; frame-ancestors 'none'",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	} {
		if got := response.Header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

func TestOfflineAccessRefreshRotationAndReuseRejection(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	params := validAuthorizeParams()
	params.Set("scope", "openid profile email offline_access")
	interaction := begin(t, p, client, params)
	code := selectPersona(t, p, client, interaction, "acme-admin")
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
	rotatedRefresh := rotated["refresh_token"].(string)
	statuses := make(chan int, 8)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			response, err := http.PostForm(p.baseURL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"dashboard"}, "refresh_token": {rotatedRefresh}})
			if err != nil {
				statuses <- 0
				return
			}
			response.Body.Close()
			statuses <- response.StatusCode
		})
	}
	wg.Wait()
	close(statuses)
	successes := 0
	for status := range statuses {
		if status == http.StatusOK {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent refresh successes = %d, want 1", successes)
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

func TestRefreshScopeValidationAndDownscoping(t *testing.T) {
	p := newTestProvider(t, 5*time.Minute)
	client := browserClient(t)
	params := validAuthorizeParams()
	params.Set("scope", "openid profile email offline_access")
	interaction := begin(t, p, client, params)
	code := selectPersona(t, p, client, interaction, "acme-admin")
	initial := exchange(t, p, client, code, verifier)
	refresh := initial["refresh_token"].(string)

	response, err := client.PostForm(p.baseURL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"dashboard"}, "refresh_token": {refresh}, "scope": {"openid bogus"}})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid refresh scope status = %d", response.StatusCode)
	}

	response, err = client.PostForm(p.baseURL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"dashboard"}, "refresh_token": {refresh}, "scope": {"openid profile"}})
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var refreshed map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&refreshed); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || refreshed["scope"] != "openid profile" {
		t.Fatalf("refresh downscoping failed: status=%d body=%#v", response.StatusCode, refreshed)
	}
	claims := jwtClaims(t, p, refreshed["id_token"].(string))
	if _, ok := claims["email"]; ok {
		t.Fatalf("downscoped ID token retained email: %#v", claims)
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
