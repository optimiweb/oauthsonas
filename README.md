# oauthsonas

`oauthsonas` is a small, in-memory OpenID Connect provider for local development and integration tests. It implements a real browser Authorization Code flow with S256 PKCE, rotating refresh tokens, RS256 JWT access and ID tokens, discovery, JWKS, userinfo, logout, and configurable personas.

## Objectives

- Replace an external OIDC provider during local development and integration tests without bypassing the relying party's real browser flow.
- Exercise discovery, Authorization Code + S256 PKCE, callback-state preservation, token exchange, JWKS validation, userinfo, logout, and refresh-token rotation.
- Provide stable application claims compatible with the future Auth0 post-login contract: `https://myo.optimicdn.com/roles`, optional `org_id`, and optional memberships.
- Keep identities reproducible in YAML while leaving application authorization and role-to-permission expansion to the relying application.
- Remain intentionally minimal: no database, password authentication, user provisioning, Auth0 Management API, or production deployment support.

## Security warning

**Development and test use only. Never expose this server to the internet or deploy it to production.** It has an in-memory persona picker instead of real authentication, generates a new signing key on every start, and has no persistent state. It binds to `127.0.0.1` by default and refuses non-loopback addresses unless `TESTOIDC_ALLOW_NON_LOOPBACK=true` is set deliberately.

## Quick usage

1. Start the provider with the example client and personas:

   ```sh
   go run ./cmd/oauthsonas --config config.example.yaml
   ```

2. Configure the dashboard with the values in [Dashboard example](#dashboard-example).
3. Start the dashboard login flow and choose a persona in the local authorization page, such as **Acme Administrator**.
4. The dashboard callback receives a normal authorization code; its OIDC library exchanges it and validates the RS256 tokens against the published JWKS.

## Run locally

```sh
go run ./cmd/oauthsonas --config config.example.yaml
```

Validate a configuration without starting the server:

```sh
go run ./cmd/oauthsonas --config config.example.yaml --check-config
```

Discovery is available at:

```text
http://127.0.0.1:8181/.well-known/openid-configuration
```

The default issuer is exactly `http://127.0.0.1:8181`. Do not substitute `localhost` in client configuration: OIDC issuer matching is exact.

## Run in a container

```sh
podman build -t oauthsonas -f Containerfile .
podman run --rm -p 127.0.0.1:8181:8181 oauthsonas
```

Docker uses the same commands with `docker` in place of `podman`.

The Containerfile intentionally sets `TESTOIDC_ALLOW_NON_LOOPBACK=true`, because a container must bind to `0.0.0.0` for its loopback-only published port to be reachable. Keep the published port loopback-bound as shown.

Published releases are available from GitHub Container Registry after a SemVer Git tag is pushed:

```sh
podman pull ghcr.io/optimiweb/oauthsonas:1.2.3
podman run --rm -p 127.0.0.1:8181:8181 ghcr.io/optimiweb/oauthsonas:1.2.3
```

Pushing `v1.2.3` publishes `1.2.3`, `1.2`, `1`, and `latest`. Pre-release tags such as `v1.2.3-rc.1` publish their exact version only and do not move `latest`.

## Dashboard example

Configure a browser dashboard using its OIDC library's equivalent of:

```sh
OIDC_AUTHORITY=http://127.0.0.1:8181
OIDC_CLIENT_ID=dashboard
OIDC_REDIRECT_URI=http://127.0.0.1:5173/auth/callback
OIDC_POST_LOGOUT_REDIRECT_URI=http://127.0.0.1:5173/
OIDC_SCOPE="openid profile email"
OIDC_AUDIENCE=https://api.optimicdn.test
```

The example client is public and requires S256 PKCE. The authorization page lets a developer select a configured persona; it then redirects to the dashboard callback with a normal authorization code and unchanged `state`.

## Configuration

`config.example.yaml` contains the default dashboard client and the requested platform, staff, and customer personas. YAML is decoded strictly: unknown fields fail startup rather than being ignored.

To add a persona, append a unique entry under `personas`:

```yaml
  - id: delta-viewer
    subject: testoidc|delta-viewer
    email: viewer@delta.dev.optimi.test
    name: Delta Viewer
    organization_id: org_delta
    roles: [customer-viewer]
```

Roles are carried as names only. This server never expands roles into application permissions. Add an optional top-level `allowed_roles` list if a project wants configuration-time role vocabulary validation; otherwise any non-empty role name is valid.

Client `redirect_uris` and `post_logout_redirect_uris` are exact-match registration values; they may include fixed query parameters but never fragments. `allowed_origins` permits browser CORS only for the listed origins. Token and userinfo responses apply client-specific CORS; discovery and JWKS apply CORS only to the union of registered origins, never `*`.

## Claims and keys

The server generates a 2048-bit RSA key when it starts and publishes its public component through `/.well-known/jwks.json`. Access and ID tokens are signed with RS256 and include a process-lifetime `kid`; neither unsigned nor symmetric JWTs are produced.

The stable authorization boundary is:

```json
{
  "https://myo.optimicdn.com/roles": ["customer-admin"],
  "org_id": "org_acme"
}
```

`org_id` is omitted for staff personas. `https://myo.optimicdn.com/memberships` is emitted only when configured. `email` and `email_verified` require the `email` scope; `name` requires `profile`. OAuth scopes remain protocol scopes and do not encode application permissions.

JWT `aud` values are serialized as JSON arrays by Fosite, which is valid JWT/OIDC representation: access tokens target the configured `api_audience`; ID tokens target the client ID. Future Auth0 post-login Actions should emit the exact namespaced roles-array claim and `org_id` shape above.

## Protocol behavior

- Supported flow: Authorization Code with required S256 PKCE, `response_type=code`, and `openid` scope.
- Standard scopes: `openid`, `profile`, `email`, and optional `offline_access`.
- `audience` is optional, but if supplied it must exactly equal `api_audience`; access tokens always use that API audience.
- `offline_access` issues a refresh token. Fosite rotates refresh tokens and detects/rejects reuse.
- Authorization codes are short-lived and one-time. State is returned unchanged. Nonces are copied to ID tokens.
- `GET` or `POST /userinfo` validates the bearer access token and returns the granted profile/custom claim subset.
- `GET /logout` redirects only to a registered `post_logout_redirect_uri` and returns an optional `state` value. It does not represent a persistent authenticated browser session.

## Endpoints

- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /oauth2/auth`
- `POST /oauth2/token`
- `GET|POST /userinfo`
- `GET /logout`

## Test

```sh
go test -race ./...
```

There is intentionally no database, password flow, admin API, user-provisioning UI, Auth0 Organizations API, Management API, external identity provider, or production deployment manifest.
