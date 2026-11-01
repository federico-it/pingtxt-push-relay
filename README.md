# pingtxt-push-relay

Push notifications for the pingtxt iOS app, for every self-hosted pingtxt hub.

An iOS app can receive notifications only from a server that holds the app's
Firebase / APNs credentials. Those credentials cannot ship inside every
self-hosted [pingtxt](https://github.com/federico-it/pingtxt) hub, so hubs
send their notifications to this small relay, which forwards them to Firebase
Cloud Messaging (HTTP v1 API), which delivers them through APNs.

```
pingtxt hub ──HTTPS──▶ push relay ──FCM HTTP v1──▶ Firebase ──APNs──▶ iPhone
  (hub token)            (service account)
```

- **Small and fast**: one static Go binary, standard library only, on a
  `scratch` image (about 3 MB compressed, a few MB of RAM).
- **No database**: hub tokens and device handles are derived from one secret
  (`RELAY_SECRET`), so the relay stores nothing and scales by adding copies.
- **Stores no monitor data**: messages are forwarded and forgotten. Logs hold
  hub ids and counts, never titles, bodies, tokens or IP addresses.
- **Hubs push only to their own phones**: the iOS app enrolls its FCM token for
  one hub and gets back a sealed *device handle*; a hub can open only handles
  made for it, and never sees the FCM token itself.
- **Live Activities**: the hub can start (iOS 17.2+), update and end the
  app's Live Activity through FCM, so it changes right away with the app
  closed.
- **Rate limits** per hub, per phone and per IP (registration, enrollment).
- Runs as uid 10001, no shell, read-only root filesystem friendly,
  `HEALTHCHECK` built in.

The API, the hub side and the app side are described in [docs/API.md](docs/API.md).

## Run

```sh
echo "RELAY_SECRET=$(openssl rand -base64 48)" > .env
cp ~/Downloads/your-firebase-service-account.json firebase.json
chmod 644 firebase.json   # the container runs as uid 10001
docker compose up -d
curl localhost:8080/healthz   # {"fcm":true,"status":"ok"}
```

or with plain Docker:

```sh
docker run -d --name push-relay -p 8080:8080 \
  -e RELAY_SECRET="..." \
  -e FCM_CREDENTIALS="$(base64 -w0 firebase.json)" \
  ghcr.io/federico-it/pingtxt-push-relay:latest
```

Put it behind HTTPS (Traefik / Coolify, Caddy, nginx) and set
`RELAY_TRUST_PROXY=true` so the per-IP limits see the client address.

**Keep `RELAY_SECRET` safe and never change it**: every hub token and device
handle is derived from it. A new secret logs out all hubs and all phones (they
register and enroll again by themselves, but notifications stop until they do).

## Settings

| Variable | Default | |
|---|---|---|
| `RELAY_SECRET` / `RELAY_SECRET_FILE` | (required) | 32+ characters. `openssl rand -base64 48` |
| `FCM_CREDENTIALS` / `FCM_CREDENTIALS_FILE` | | Firebase service account JSON key (the JSON or its base64). Without it `/v1/push` answers 503. |
| `RELAY_ADDR` | `:8080` | Listen address |
| `RELAY_REGISTRATION` | `open` | `open`: any hub can register (public relay). `token`: hubs need `RELAY_REGISTRATION_TOKEN`. `closed`: no new hubs, make tokens with `pingtxt-push-relay hub-token`. |
| `RELAY_REGISTRATION_TOKEN` | | For `RELAY_REGISTRATION=token` (16+ characters) |
| `RELAY_REVOKED_HUBS` | | Comma separated hub ids to block (abuse) |
| `RELAY_HUB_RATE` | `120` | Notifications per hub per minute (one per device) |
| `RELAY_DEVICE_RATE` | `30` | Notifications per phone per minute |
| `RELAY_IP_RATE` | `20` | Hub registrations + device enrollments per IP per minute |
| `RELAY_TRUST_PROXY` | `false` | Client IP from the last `X-Forwarded-For` entry |
| `FCM_DRY_RUN` | `false` | FCM validates messages but does not deliver them |
| `RELAY_LOG_LEVEL` | `info` | `debug` logs every request (method, path, status, time) |

Rate limits are in memory, per process. `0` turns a limit off.

## Firebase setup

1. Create a Firebase project and add the iOS app (bundle id of pingtxt-ios).
2. In *Project settings → Cloud Messaging → Apple app configuration*, upload
   the APNs authentication key (.p8) from the Apple developer account, with its
   Key ID and Team ID.
3. In *Project settings → Service accounts*, *Generate new private key*. That
   JSON file is `FCM_CREDENTIALS`. It only needs the *Firebase Cloud Messaging
   API Admin* role (`roles/firebasecloudmessaging.admin`) if you make a
   dedicated service account.
4. Put `GoogleService-Info.plist` of the same project in the iOS app.

## Commands

```sh
pingtxt-push-relay               # run the server
pingtxt-push-relay healthcheck   # exit 0 if the local server is healthy (Docker HEALTHCHECK)
pingtxt-push-relay hub-token     # print a new hub id + token (same RELAY_SECRET)
pingtxt-push-relay version
```

## Develop

```sh
go test -race ./...
RELAY_SECRET=$(openssl rand -base64 48) go run ./cmd/pingtxt-push-relay
docker build -t pingtxt-push-relay .
```

Images: `ghcr.io/federico-it/pingtxt-push-relay:main` from main,
`:X.Y.Z` and `:latest` from `vX.Y.Z` tags, multi-arch (amd64, arm64), signed
with cosign (keyless).

## License

AGPL-3.0, like pingtxt.
