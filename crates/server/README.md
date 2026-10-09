# surf-rac-server

Signaling and account server for surf-rac: team accounts, device registry,
contact book, presence, WebRTC signaling relay and TURN credentials. One
binary, one Postgres database, one instance.

## Build

```sh
docker build -f crates/server/Dockerfile -t surf-rac-server .
```

Tests run in Docker and need no local Rust toolchain:

```sh
docker compose -f compose.test.yaml run --rm test
```

## Configuration

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `DATABASE_URL` | yes | | Postgres URL, e.g. `postgres://surfrac:…@db/surfrac` |
| `TURN_SECRET` | yes | | coturn `static-auth-secret`, at least 16 characters |
| `TURN_URLS` | yes | | Comma-separated TURN URLs handed to clients, e.g. `turn:turn.example.com:3478` |
| `TURN_TTL_SECS` | no | `3600` | Lifetime of issued TURN credentials |
| `LIVEKIT_URL` | yes | | LiveKit URL handed to clients, `ws://` or `wss://`, e.g. `wss://rac-livekit.slne.dev` |
| `LIVEKIT_API_KEY` | yes | | LiveKit API key that issues join tokens |
| `LIVEKIT_API_SECRET` | yes | | LiveKit API secret, at least 32 characters, the same as in the LiveKit `keys` setting |
| `BIND_ADDR` | no | `0.0.0.0:8080` | Listen address |
| `TRUST_FORWARDED_FOR` | no | `false` | Use the right-most `X-Forwarded-For` entry as client IP. Set `true` only behind a proxy that appends it (Traefik) |
| `LOG_FORMAT` | no | `json` | `json` or `pretty` |
| `RUST_LOG` | no | `info` | Log filter |

The server refuses to start when a required value is missing or invalid.
Migrations run automatically on start and are forward-only. Migration
`0003_device_identity` drops every user, session, device and contact and
creates the device-identity schema, so the image before it does not work
against a migrated database; rolling back past it needs the database backup.

## Deploying on Coolify

1. Create a Postgres 17 resource and enable scheduled backups for it. The
   database is the source of truth for accounts and devices.
2. Create an application from this image (or from the repository with the
   Dockerfile above, build context = repository root). Port `8080`.
3. Set the environment variables above, with `TRUST_FORWARDED_FOR=true`.
4. Give it a domain. Traefik terminates TLS for both `https://` and `wss://`;
   WebSocket upgrades need no extra configuration.
5. Health check: `GET /healthz` returns 200 when the database is reachable.

Rollback: redeploy the previous image tag.

## coturn

coturn must use the same secret:

```
use-auth-secret
static-auth-secret=<TURN_SECRET>
```

## Admin CLI

Run inside the container (Coolify terminal, or `docker exec -it <container>`):

```sh
surf-rac-server create-admin <username>       # password from SURF_RAC_PASSWORD or stdin
surf-rac-server create-invite [--expires-hours 72]
surf-rac-server list-invites
surf-rac-server revoke-invite <id>
surf-rac-server list-users
surf-rac-server disable-user <username>       # also revokes sessions
surf-rac-server enable-user <username>
surf-rac-server reset-password <username>     # also revokes sessions
surf-rac-server revoke-sessions <username>
```

Invite codes are printed once and stored only as hashes. Disabled users and
revoked sessions lose their WebSocket within a minute.

## API

All endpoints are under `/v1`. The wire types are defined in the
`surf-rac-protocol` crate.

- `POST /register`, `POST /login`, `POST /logout`
- `POST /devices`: registers an installation without an account. Body:
  `public_key` (standard base64 of the 32-byte Ed25519 identity public key),
  `fingerprint_hash` (64 lowercase hex characters), `name` (1 to 64
  characters) and `protocol_version`. Returns the 9-digit `device_id`. The
  same key and fingerprint return the existing ID and update the name; the
  same key with another fingerprint is a 409 `clone_detected`; another
  protocol version is a 426 `update_required`.
- `GET /devices`, `DELETE /devices/{id}`: the devices linked to the account
- `GET /contacts`, `PUT /contacts/{id}`, `DELETE /contacts/{id}`
- `GET /presence/{id}`: online state of a device
- `GET /ws`: WebSocket. Send `X-Device-Id` and `X-Protocol-Version` on the
  upgrade request; another or a missing version is a 426 `update_required`,
  an unknown or disabled device a 401. The server then sends `challenge` with
  a random 32-byte nonce, and the device must answer within 10 seconds with
  `authenticate`: an Ed25519 signature over `surf-rac/challenge/v1` followed
  by the nonce, and its fingerprint hash. A wrong signature closes the socket
  with `bad_signature`, a different fingerprint with `clone_detected`; a valid
  answer is followed by `hello`. Besides `signal` relaying it
  carries session negotiation (`session_request`, `password_challenge`,
  `session_password`, `session_response`) and
  LiveKit tokens: `host_token_request` returns a token for the device's own
  room `host-<device_id>`; `viewer_token_request` sends a 60-second
  subscribe-only token for that room to the named viewer.
