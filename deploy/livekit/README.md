# LiveKit for surf-rac

Self-hosted LiveKit SFU that carries session media and data. It runs next to
the signaling server on the VPS `31.70.103.18`. Media and data are end-to-end
encrypted by the clients, so the server only forwards ciphertext.

## Network

| Purpose | Reached as |
|---|---|
| LiveKit signaling (WebSocket) | `wss://rac-livekit.slne.dev` through a Cloudflare Tunnel to `http://localhost:7880` |
| Signaling server | `wss://rac.slne.dev` through a Cloudflare Tunnel to `http://localhost:18080` |
| Media over UDP | `31.70.103.18`, UDP 50000-60000 |
| Media over TCP fallback | `31.70.103.18`, TCP 7881 |
| Embedded TURN | `31.70.103.18`, UDP 3478 |

Open UDP 50000-60000, TCP 7881 and UDP 3478 in the VPS firewall. Media cannot go
through the Cloudflare Tunnel; only the two WebSocket hostnames do.

The embedded TURN server does not relay to private addresses, so the node must
advertise its public IP (`use_external_ip: true`).

## Run

```sh
cd deploy/livekit
export LIVEKIT_KEYS="<key>: <secret>"   # secret: at least 32 characters
docker compose up -d
```

The signaling server needs the same key and secret:

```
LIVEKIT_URL=wss://rac-livekit.slne.dev
LIVEKIT_API_KEY=<key>
LIVEKIT_API_SECRET=<secret>
```

Rooms hold at most six participants (one host, five viewers) and close five
minutes after the last participant leaves.

## Measure latency through the VPS

The latency test of the session crate uses whatever LiveKit the environment
names. Point it at the VPS to measure the real path:

```sh
docker compose -f compose.test.yaml run --rm \
  -e LIVEKIT_URL=wss://rac-livekit.slne.dev \
  -e LIVEKIT_API_KEY=<key> -e LIVEKIT_API_SECRET=<secret> \
  test cargo test -p surf-rac-session --test session median_frame_delay_under_200ms -- --nocapture
```

The test prints the median one-way frame delay and fails above 200 ms.

## Upgrade and rollback

Change the pinned image tag in `compose.yaml` and run `docker compose up -d`.
Roll back by restoring the previous tag. LiveKit keeps no persistent state.
