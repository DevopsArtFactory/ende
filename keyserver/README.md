# Ende Keyserver

Optional public key directory for Ende peer onboarding.

The keyserver stores public peer profiles only. It does not store private keys,
does not decrypt envelopes, and should not replace Ende's local keyring pinning
model. Clients should still confirm and pin fetched keys locally.

## API

- `GET /health`
- `GET /v1/peers/{id}`
- `PUT /v1/peers/{id}`
- `DELETE /v1/peers/{id}`
- `GET /v1/share/{id}`

`PUT` and `DELETE` require a bearer token when `ENDE_KEYSERVER_ADMIN_TOKEN` is set.

Profile shape:

```json
{
  "id": "alice",
  "recipient": "age1...",
  "signing_public": "base64-ed25519-public-key",
  "display_name": "Alice",
  "updated_at": "2026-05-04T00:00:00Z"
}
```

`GET /v1/share/{id}` returns a share-code compatible payload:

```json
{
  "share_code": "ENDE-PUB-1:..."
}
```

## CLI Flow

Publish your local public profile:

```bash
export ENDE_KEYSERVER_URL=https://keys.example.com
ende keyserver login --name alice
ende keyserver publish --name alice
```

Okta login:

```bash
ende keyserver login --provider okta --name alice
ende keyserver publish --name alice
```

Fetch and pin a peer:

```bash
ende peer fetch bob
```

Refresh a pinned peer after a key rotation:

```bash
ende peer refresh bob
ende peer refresh bob --yes
```

`refresh` prints the old and new fingerprints and refuses to overwrite local pins unless `--yes` is set.

## SSO Token Issuing

The CLI performs GitHub or Okta device login, sends the provider access token to
`POST /v1/auth/{provider}`, and stores the returned Ende publish token locally.
The keyserver stores only a SHA-256 hash of the Ende token.

Supported auth endpoints:

- `GET /v1/auth/config`
- `POST /v1/auth/github`
- `POST /v1/auth/okta`

The CLI reads `GET /v1/auth/config` before device login, so users do not need to
pass OAuth client IDs manually. Configure provider metadata on the keyserver:

```bash
ENDE_KEYSERVER_DEFAULT_PROVIDER=github
ENDE_KEYSERVER_GITHUB_CLIENT_ID=<github-oauth-client-id>
ENDE_KEYSERVER_OKTA_CLIENT_ID=<okta-client-id>
ENDE_KEYSERVER_OKTA_ISSUER=https://example.okta.com/oauth2/default
```

Auth request shape:

```json
{
  "access_token": "provider-access-token",
  "peer_id": "alice"
}
```

Auth response shape:

```json
{
  "token": "ende_ks_...",
  "peer_id": "alice",
  "provider": "github",
  "subject": "alice"
}
```

Per-user tokens can publish only their own `peer_id`. Admin tokens can still
manage all peers.

## Run Locally

```bash
python3 -m keyserver.ende_keyserver
```

## Docker Compose Smoke Test

From the repository root:

```bash
make compose-test
make compose-down
```

The compose setup starts the Python keyserver and runs a Go CLI smoke test that:

- initializes Alice and Bob
- logs Alice in with dev-mode GitHub auth
- logs Bob in with dev-mode Okta auth
- publishes both public profiles
- fetches and pins peers from the keyserver
- sends and receives a test secret

`ENDE_KEYSERVER_DEV_AUTH=1` is enabled only in the compose test service so the
flow can run without real GitHub or Okta credentials.

Default settings:

- backend: `file`
- bind: `127.0.0.1`
- port: `8765`
- file path: `.ende-keyserver.json`

## Configuration

```bash
ENDE_KEYSERVER_BACKEND=file
ENDE_KEYSERVER_FILE=.ende-keyserver.json
ENDE_KEYSERVER_HOST=127.0.0.1
ENDE_KEYSERVER_PORT=8765
ENDE_KEYSERVER_ADMIN_TOKEN=change-me
ENDE_KEYSERVER_REQUIRE_AUTH=1
ENDE_KEYSERVER_ALLOWED_PEERS=alice,bob
ENDE_KEYSERVER_IDENTITY_MAP=github:alice=alice,okta:alice@example.com=alice
ENDE_KEYSERVER_OKTA_ISSUER=https://example.okta.com/oauth2/default
```

## DynamoDB Backend

DynamoDB is a good fit for this service because profiles are small documents
looked up by a single key. Use one table with a string partition key named `id`.

```bash
ENDE_KEYSERVER_BACKEND=dynamodb
ENDE_KEYSERVER_DDB_TABLE=ende-peer-keys
ENDE_KEYSERVER_AWS_REGION=ap-northeast-2
ENDE_KEYSERVER_ADMIN_TOKEN=change-me
python3 -m keyserver.ende_keyserver
```

Required item shape is the same as the profile JSON. The DynamoDB backend imports
`boto3` only when selected.

## Security Notes

- Treat this service as a public directory, not a trust root.
- Keep Ende's local keyring pinning as the final trust decision.
- Require TLS in production.
- Use `ENDE_KEYSERVER_ADMIN_TOKEN` or an API gateway authorizer for writes.
- Key rotation should show diffs to clients before local pins are updated.
