package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/optimiweb/oauthsonas/internal/config"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
)

const (
	rolesClaim        = "https://myo.optimicdn.com/roles"
	membershipsClaim  = "https://myo.optimicdn.com/memberships"
	interactionCookie = "oauthsonas_interaction"
)

type Server struct {
	config       *config.Config
	provider     fosite.OAuth2Provider
	store        *storage.MemoryStore
	key          jose.JSONWebKey
	clients      map[string]config.Client
	personas     map[string]config.Persona
	interactions interactionStore
	tokenMu      sync.Mutex
	template     *template.Template
}

type oidcClient struct {
	*fosite.DefaultOpenIDConnectClient
	responseModes []fosite.ResponseModeType
}

func (c *oidcClient) GetResponseModes() []fosite.ResponseModeType { return c.responseModes }

type session struct {
	*openid.DefaultSession
	JWTClaims *jwt.JWTClaims `json:"jwt_claims"`
	JWTHeader *jwt.Headers   `json:"jwt_header"`
}

func newSession() *session {
	return &session{DefaultSession: openid.NewDefaultSession(), JWTClaims: &jwt.JWTClaims{Extra: map[string]interface{}{}}, JWTHeader: &jwt.Headers{}}
}

func (s *session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.JWTClaims == nil {
		s.JWTClaims = &jwt.JWTClaims{Extra: map[string]interface{}{}}
	}
	if s.JWTClaims.Extra == nil {
		s.JWTClaims.Extra = map[string]interface{}{}
	}
	return s.JWTClaims
}

func (s *session) GetJWTHeader() *jwt.Headers {
	if s.JWTHeader == nil {
		s.JWTHeader = &jwt.Headers{}
	}
	return s.JWTHeader
}

func (s *session) Clone() fosite.Session {
	// JSON round-tripping preserves every exported claim required during refresh.
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	clone := newSession()
	if err := json.Unmarshal(b, clone); err != nil {
		panic(err)
	}
	if clone.DefaultSession == nil {
		clone.DefaultSession = openid.NewDefaultSession()
	}
	return clone
}

type interaction struct {
	request fosite.AuthorizeRequester
	csrf    string
	expires time.Time
}

type interactionStore struct {
	mu sync.Mutex
	m  map[string]interaction
}

func (s *interactionStore) put(request fosite.AuthorizeRequester) (id, csrf string, err error) {
	id, err = randomString(32)
	if err != nil {
		return "", "", err
	}
	csrf, err = randomString(32)
	if err != nil {
		return "", "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string]interaction{}
	}
	now := time.Now()
	for key, value := range s.m {
		if now.After(value.expires) {
			delete(s.m, key)
		}
	}
	s.m[id] = interaction{request: request, csrf: csrf, expires: now.Add(5 * time.Minute)}
	return id, csrf, nil
}

func (s *interactionStore) take(id, csrf string) (fosite.AuthorizeRequester, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.m[id]
	if !ok || time.Now().After(value.expires) || subtle.ConstantTimeCompare([]byte(value.csrf), []byte(csrf)) != 1 {
		return nil, false
	}
	delete(s.m, id)
	return value.request, true
}

func New(c *config.Config) (*Server, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	kid, err := randomString(12)
	if err != nil {
		return nil, err
	}
	key := jose.JSONWebKey{Key: privateKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generate server secret: %w", err)
	}

	fc := &fosite.Config{
		GlobalSecret:                   secret,
		IDTokenIssuer:                  c.Issuer,
		AccessTokenIssuer:              c.Issuer,
		AccessTokenLifespan:            c.TokenTTLDuration,
		IDTokenLifespan:                c.TokenTTLDuration,
		AuthorizeCodeLifespan:          c.AuthorizationCodeTTLD,
		RefreshTokenLifespan:           c.RefreshTokenTTLDuration,
		EnforcePKCE:                    true,
		EnablePKCEPlainChallengeMethod: false,
		ScopeStrategy:                  fosite.ExactScopeStrategy,
		AudienceMatchingStrategy:       fosite.ExactAudienceMatchingStrategy,
		RefreshTokenScopes:             []string{"offline_access"},
		JWTScopeClaimKey:               jwt.JWTScopeFieldString,
	}
	keyGetter := func(context.Context) (interface{}, error) { return &key, nil }
	hmacStrategy := compose.NewOAuth2HMACStrategy(fc)
	jwtStrategy := compose.NewOAuth2JWTStrategy(keyGetter, hmacStrategy, fc)
	oidcStrategy := compose.NewOpenIDConnectStrategy(keyGetter, fc)
	strategy := compose.CommonStrategy{CoreStrategy: jwtStrategy, OpenIDConnectTokenStrategy: oidcStrategy, Signer: &jwt.DefaultSigner{GetPrivateKey: keyGetter}}
	store := storage.NewMemoryStore()
	clients := make(map[string]config.Client, len(c.Clients))
	for _, client := range c.Clients {
		clients[client.ID] = client
		baseClient := &fosite.DefaultClient{
			ID: client.ID, RedirectURIs: client.RedirectURIs, Public: true,
			GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"},
			Scopes: []string{"openid", "profile", "email", "offline_access"}, Audience: []string{c.APIAudience},
		}
		store.Clients[client.ID] = &oidcClient{
			DefaultOpenIDConnectClient: &fosite.DefaultOpenIDConnectClient{DefaultClient: baseClient, TokenEndpointAuthMethod: "none"},
			responseModes:              []fosite.ResponseModeType{fosite.ResponseModeQuery},
		}
	}
	provider := compose.Compose(fc, store, strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OpenIDConnectExplicitFactory,
		compose.OpenIDConnectRefreshFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)
	personas := make(map[string]config.Persona, len(c.Personas))
	for _, p := range c.Personas {
		personas[p.ID] = p
	}
	s := &Server{config: c, provider: provider, store: store, key: key, clients: clients, personas: personas, template: personaTemplate}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/.well-known/jwks.json", s.jwks)
	mux.HandleFunc("/oauth2/auth", s.authorize)
	mux.HandleFunc("/oauth2/auth/select", s.selectPersona)
	mux.HandleFunc("/oauth2/token", s.token)
	mux.HandleFunc("/userinfo", s.userinfo)
	mux.HandleFunc("/logout", s.logout)
	return mux
}

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "Origin")
	if r.Method == http.MethodOptions {
		s.applyUnionCORS(w, r, []string{http.MethodGet})
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.applyUnionCORS(w, r, []string{"GET"}) {
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	endpoint := s.config.Issuer
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"issuer": endpoint, "authorization_endpoint": endpoint + "/oauth2/auth", "token_endpoint": endpoint + "/oauth2/token",
		"userinfo_endpoint": endpoint + "/userinfo", "jwks_uri": endpoint + "/.well-known/jwks.json", "end_session_endpoint": endpoint + "/logout",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
		"scopes_supported": []string{"openid", "profile", "email", "offline_access"}, "code_challenge_methods_supported": []string{"S256"},
		"subject_types_supported": []string{"public"}, "claims_supported": []string{"sub", "email", "email_verified", "name", rolesClaim, "org_id", membershipsClaim},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"none"},
		"response_modes_supported": []string{"query"}, "request_uri_parameter_supported": false,
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Vary", "Origin")
	if r.Method == http.MethodOptions {
		s.applyUnionCORS(w, r, []string{http.MethodGet})
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if !s.applyUnionCORS(w, r, []string{"GET"}) {
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	public := s.key.Public()
	public.Algorithm, public.Use, public.KeyID = string(jose.RS256), "sig", s.key.KeyID
	writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{public}})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	ar, err := s.provider.NewAuthorizeRequest(r.Context(), r)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, ar, err)
		return
	}
	if err := s.validateBrowserRequest(r); err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, ar, err)
		return
	}
	if !ar.GetRequestedScopes().Has("openid") {
		s.provider.WriteAuthorizeError(r.Context(), w, ar, fosite.ErrInvalidScope.WithHint("openid scope is required"))
		return
	}
	id, csrf, err := s.interactions.put(ar)
	if err != nil {
		http.Error(w, "could not create interaction", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: interactionCookie + "_" + id, Value: id, Path: "/oauth2", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.template.Execute(w, struct {
		Personas      []config.Persona
		CSRF          string
		InteractionID string
	}{personasSlice(s.personas), csrf, id}); err != nil {
		return
	}
}

func (s *Server) validateBrowserRequest(r *http.Request) error {
	q := r.URL.Query()
	for _, name := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "audience", "response_mode"} {
		if len(q[name]) > 1 {
			return fosite.ErrInvalidRequest.WithHintf("%s must not be repeated", name)
		}
	}
	if q.Get("redirect_uri") == "" {
		return fosite.ErrInvalidRequest.WithHint("redirect_uri is required")
	}
	if q.Get("response_type") != "code" {
		return fosite.ErrInvalidRequest.WithHint("only response_type=code is supported")
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		return fosite.ErrInvalidRequest.WithHint("PKCE S256 code_challenge is required")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(challenge) != 43 || len(decoded) != 32 {
		return fosite.ErrInvalidRequest.WithHint("code_challenge must be a SHA-256 base64url value")
	}
	client, ok := s.clients[q.Get("client_id")]
	if ok && !contains(client.RedirectURIs, q.Get("redirect_uri")) {
		return fosite.ErrInvalidRequest.WithHint("redirect_uri must exactly match a registered redirect_uri")
	}
	if nonce := q.Get("nonce"); nonce != "" && len(nonce) < fosite.MinParameterEntropy {
		return fosite.ErrInvalidRequest.WithHint("nonce must have sufficient entropy")
	}
	if audiences, present := q["audience"]; present && (len(audiences) != 1 || audiences[0] != s.config.APIAudience) {
		return fosite.ErrInvalidRequest.WithHint("audience must exactly equal the configured api_audience")
	}
	return nil
}

func (s *Server) selectPersona(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	interactionID := r.Form.Get("interaction_id")
	if !validInteractionID(interactionID) {
		http.Error(w, "invalid interaction", http.StatusForbidden)
		return
	}
	cookie, err := r.Cookie(interactionCookie + "_" + interactionID)
	if err != nil || cookie.Value != interactionID {
		http.Error(w, "invalid interaction", http.StatusForbidden)
		return
	}
	p, ok := s.personas[r.Form.Get("persona")]
	if !ok {
		http.Error(w, "unknown persona", http.StatusBadRequest)
		return
	}
	ar, ok := s.interactions.take(interactionID, r.Form.Get("csrf"))
	if !ok {
		http.Error(w, "invalid interaction", http.StatusForbidden)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: interactionCookie + "_" + interactionID, Value: "", Path: "/oauth2", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	ar.GrantAudience(s.config.APIAudience)
	session := s.personaSession(p, ar)
	resp, err := s.provider.NewAuthorizeResponse(r.Context(), ar, session)
	if err != nil {
		s.provider.WriteAuthorizeError(r.Context(), w, ar, err)
		return
	}
	s.provider.WriteAuthorizeResponse(r.Context(), w, ar, resp)
}

func (s *Server) personaSession(p config.Persona, ar fosite.AuthorizeRequester) *session {
	session := newSession()
	session.Subject, session.DefaultSession.Subject = p.Subject, p.Subject
	session.Claims.Subject = p.Subject
	session.Claims.AuthTime = time.Now().UTC()
	claims := session.JWTClaims
	claims.Subject = p.Subject
	claims.Extra["client_id"] = ar.GetClient().GetID()
	roles := append([]string(nil), p.Roles...)
	claims.Extra[rolesClaim] = roles
	session.Claims.Extra = map[string]interface{}{rolesClaim: roles}
	if ar.GetGrantedScopes().Has("email") {
		session.Claims.Extra["email"] = p.Email
		session.Claims.Extra["email_verified"] = true
	}
	if ar.GetGrantedScopes().Has("profile") {
		session.Claims.Extra["name"] = p.Name
	}
	if p.OrganizationID != "" {
		claims.Extra["org_id"] = p.OrganizationID
		session.Claims.Extra["org_id"] = p.OrganizationID
	}
	if len(p.Memberships) != 0 {
		memberships := append([]string(nil), p.Memberships...)
		claims.Extra[membershipsClaim] = memberships
		session.Claims.Extra[membershipsClaim] = memberships
	}
	return session
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if !s.applyTokenCORS(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	for _, name := range []string{"grant_type", "client_id", "client_secret", "code", "redirect_uri", "code_verifier", "refresh_token", "scope"} {
		if len(r.Form[name]) > 1 {
			s.provider.WriteAccessError(r.Context(), w, nil, fosite.ErrInvalidRequest.WithHintf("%s must not be repeated", name))
			return
		}
	}
	requestedScope, scopeProvided := r.Form["scope"]

	// MemoryStore does not provide transactional refresh-token rotation. Serialize
	// token handling so a refresh token cannot be exchanged concurrently.
	s.tokenMu.Lock()
	defer s.tokenMu.Unlock()
	accessRequest, err := s.provider.NewAccessRequest(r.Context(), r, newSession())
	if err != nil {
		s.provider.WriteAccessError(r.Context(), w, accessRequest, err)
		return
	}
	if accessRequest.GetGrantTypes().Has("refresh_token") {
		if err := applyRefreshScope(accessRequest, requestedScope, scopeProvided); err != nil {
			s.provider.WriteAccessError(r.Context(), w, accessRequest, err)
			return
		}
		if session, ok := accessRequest.GetSession().(*session); ok {
			session.JWTClaims.IssuedAt = time.Time{}
			session.JWTClaims.JTI = ""
			removeScopeClaims(session, accessRequest.GetGrantedScopes())
		}
	}
	response, err := s.provider.NewAccessResponse(r.Context(), accessRequest)
	if err != nil {
		s.provider.WriteAccessError(r.Context(), w, accessRequest, err)
		return
	}
	s.provider.WriteAccessResponse(r.Context(), w, accessRequest, response)
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		s.applyUnionCORS(w, r, []string{"GET", "POST"})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodGet+", "+http.MethodPost)
		return
	}
	token, err := bearerToken(r)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_request"`)
		http.Error(w, "invalid bearer token transport", http.StatusBadRequest)
		return
	}
	_, accessRequest, err := s.provider.IntrospectToken(r.Context(), token, fosite.AccessToken, newSession())
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "invalid access token", http.StatusUnauthorized)
		return
	}
	client := s.clients[accessRequest.GetClient().GetID()]
	if !s.applyClientCORS(w, r, client, []string{"GET", "POST"}) {
		return
	}
	session, ok := accessRequest.GetSession().(*session)
	if !ok {
		http.Error(w, "invalid session", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	result := map[string]interface{}{"sub": session.GetSubject()}
	for _, key := range []string{rolesClaim, "org_id", membershipsClaim} {
		if value, ok := session.Claims.Extra[key]; ok {
			result[key] = value
		}
	}
	if accessRequest.GetGrantedScopes().Has("email") {
		for _, key := range []string{"email", "email_verified"} {
			if value, ok := session.Claims.Extra[key]; ok {
				result[key] = value
			}
		}
	}
	if accessRequest.GetGrantedScopes().Has("profile") {
		if value, ok := session.Claims.Extra["name"]; ok {
			result["name"] = value
		}
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	uri, clientID := r.URL.Query().Get("post_logout_redirect_uri"), r.URL.Query().Get("client_id")
	if uri == "" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("logged out\n"))
		return
	}
	if !s.validPostLogoutURI(clientID, uri) {
		http.Error(w, "unregistered post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	redirect, err := url.Parse(uri)
	if err != nil {
		http.Error(w, "invalid post_logout_redirect_uri", http.StatusBadRequest)
		return
	}
	if state := r.URL.Query().Get("state"); state != "" {
		query := redirect.Query()
		query.Set("state", state)
		redirect.RawQuery = query.Encode()
	}
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

func (s *Server) validPostLogoutURI(clientID, target string) bool {
	if clientID != "" {
		client, ok := s.clients[clientID]
		if !ok {
			return false
		}
		return contains(client.PostLogoutRedirectURIs, target)
	}
	for _, client := range s.clients {
		if contains(client.PostLogoutRedirectURIs, target) {
			return true
		}
	}
	return false
}

func (s *Server) applyTokenCORS(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodOptions {
		return s.applyUnionCORS(w, r, []string{"POST"})
	}
	if r.Header.Get("Origin") == "" {
		return true
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	client, ok := s.clients[r.Form.Get("client_id")]
	if !ok {
		return true
	} // Fosite returns the OAuth error; never grant CORS to unknown clients.
	return s.applyClientCORS(w, r, client, []string{"POST"})
}

func (s *Server) applyUnionCORS(w http.ResponseWriter, r *http.Request, methods []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if r.Method == http.MethodOptions {
			methodNotAllowed(w, strings.Join(methods, ", "))
			return false
		}
		return true
	}
	w.Header().Set("Vary", "Origin")
	for _, client := range s.clients {
		if contains(client.AllowedOrigins, origin) {
			setCORS(w, origin, methods)
			return r.Method != http.MethodOptions || writeNoContent(w)
		}
	}
	if r.Method == http.MethodOptions {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) applyClientCORS(w http.ResponseWriter, r *http.Request, client config.Client, methods []string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	w.Header().Set("Vary", "Origin")
	if !contains(client.AllowedOrigins, origin) {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return false
	}
	setCORS(w, origin, methods)
	if r.Method == http.MethodOptions {
		return writeNoContent(w)
	}
	return true
}

func setCORS(w http.ResponseWriter, origin string, methods []string) {
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
}

func writeNoContent(w http.ResponseWriter) bool { w.WriteHeader(http.StatusNoContent); return false }

func methodNotAllowed(w http.ResponseWriter, methods string) {
	w.Header().Set("Allow", methods)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomString(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func validInteractionID(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func applyRefreshScope(request fosite.AccessRequester, values []string, provided bool) error {
	if !provided {
		return nil
	}
	scopes := fosite.Arguments(strings.Fields(values[0]))
	if len(scopes) == 0 {
		return fosite.ErrInvalidScope.WithHint("scope must not be empty")
	}
	for _, scope := range scopes {
		if !request.GetGrantedScopes().Has(scope) {
			return fosite.ErrInvalidScope.WithHint("refresh scope must be granted by the original authorization")
		}
	}
	refresh, ok := request.(*fosite.AccessRequest)
	if !ok {
		return fosite.ErrServerError.WithHint("unexpected refresh request type")
	}
	refresh.RequestedScope = scopes
	refresh.GrantedScope = scopes
	return nil
}

func removeScopeClaims(session *session, scopes fosite.Arguments) {
	if !scopes.Has("email") {
		delete(session.Claims.Extra, "email")
		delete(session.Claims.Extra, "email_verified")
	}
	if !scopes.Has("profile") {
		delete(session.Claims.Extra, "name")
	}
}

func bearerToken(r *http.Request) (string, error) {
	if r.URL.Query().Has("access_token") {
		return "", fmt.Errorf("query access tokens are not supported")
	}
	if err := r.ParseForm(); err != nil {
		return "", err
	}
	if _, ok := r.PostForm["access_token"]; ok {
		return "", fmt.Errorf("form access tokens are not supported")
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") || strings.TrimSpace(strings.TrimPrefix(values[0], "Bearer ")) == "" {
		return "", fmt.Errorf("exactly one bearer authorization header is required")
	}
	return strings.TrimSpace(strings.TrimPrefix(values[0], "Bearer ")), nil
}

func personasSlice(m map[string]config.Persona) []config.Persona {
	result := make([]config.Persona, 0, len(m))
	for _, p := range m {
		result = append(result, p)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

var personaTemplate = template.Must(template.New("persona").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Select a test persona</title><style>body{font-family:system-ui,sans-serif;max-width:44rem;margin:3rem auto;padding:0 1rem}ul{padding:0;list-style:none}li{border:1px solid #ccd;border-radius:.5rem;margin:.75rem 0;padding:1rem}button{font:inherit;padding:.45rem .8rem;cursor:pointer}.meta{color:#445;margin:.25rem 0}.roles{font-family:ui-monospace,monospace}</style></head><body><main><h1>Select a test persona</h1><p>This local development server will complete a real OpenID Connect authorization flow.</p><ul>{{range .Personas}}<li><strong>{{.Name}}</strong><div class="meta">{{.Email}}</div><div class="meta roles">roles: {{range $i, $r := .Roles}}{{if $i}}, {{end}}{{$r}}{{end}}</div>{{if .OrganizationID}}<div class="meta">organization: {{.OrganizationID}}</div>{{end}}{{if .Memberships}}<div class="meta">memberships: {{range $i, $m := .Memberships}}{{if $i}}, {{end}}{{$m}}{{end}}</div>{{end}}<form method="post" action="/oauth2/auth/select"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="interaction_id" value="{{$.InteractionID}}"><button name="persona" value="{{.ID}}" type="submit">Continue as {{.Name}}</button></form></li>{{end}}</ul></main></body></html>`))
