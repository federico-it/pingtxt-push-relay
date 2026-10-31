# Push relay API and integration

Three parties talk to the relay:

1. **The pingtxt hub** registers once, then sends notifications.
2. **The iOS app** turns its FCM token into a device handle for one hub.
3. **Operators** check `/healthz`.

All bodies are JSON (max 64 KB). Errors look like
`{"error": "invalid_request", "message": "title: required, at most 200 bytes"}`.
Every 429 has a `Retry-After` header (seconds).

The official relay is `https://push.pingtxt.com` (base URL in the examples).
A hub can use another relay, but phones only accept messages from the relay
that holds the Firebase key of the app build they run.

## Flow

```
hub (first start of the feature)
  POST /v1/hubs                          → hub_id + hub_token   (saved in hub settings)

app (after sign-in to a hub, and whenever FCM rotates its token)
  GET  {hub}/api/mobile/config             → relay_url, hub_id    (hub API)
  Firebase SDK                           → fcm_token
  POST {relay}/v1/devices {hub_id, fcm_token} → device handle "prd_…"
  POST {hub}/api/mobile/devices {device, name}                  (hub API)

hub (alert: monitor down / up, incident, …)
  POST {relay}/v1/push  Bearer hub_token  {devices: [...], title, body, …}
  ← results per device; "gone" → delete that device in the hub
```

## Credentials

- **Hub token** `prh_<hub_id>.<mac>`: secret, kept by the hub (write-only in
  its settings), sent as `Authorization: Bearer` on `/v1/push` and
  `/v1/hubs/me`. `hub_id` alone is public: the app needs it.
- **Device handle** `prd_…`: the phone's FCM token and the hub id, encrypted by
  the relay (AES-256-GCM). Only that hub can push with it. Not a secret on its
  own (useless without the hub token), but the hub should not expose it to
  other users.

Both are derived from `RELAY_SECRET`: the relay has no database, and nothing
can be listed or leaked from it.

## Endpoints

### `POST /v1/hubs` — register a hub

No body. With `RELAY_REGISTRATION=token`: `Authorization: Bearer <registration token>`.

`201 {"hub_id": "PrBlwRm8tbClvg8f5PEy4w", "hub_token": "prh_PrBlwRm8tbClvg8f5PEy4w.z-sK…"}`

`401` wrong registration token · `403 registration_closed` · `429` per-IP limit.

Call it once and keep the result. Registering again makes a new hub id: the
phones enrolled with the old one must enroll again.

### `GET /v1/hubs/me` — check the hub token

`Authorization: Bearer <hub_token>` → `200 {"hub_id": "…", "fcm": true}`.
`401` bad token · `403 hub_revoked`. For a "Test connection" button.

### `POST /v1/devices` — enroll a phone (called by the app)

```json
{"hub_id": "PrBlwRm8tbClvg8f5PEy4w", "fcm_token": "<Messaging.messaging().fcmToken>"}
```

`201 {"device": "prd_AeYWsf5y…"}` · `400 invalid_hub | invalid_token` ·
`403 hub_revoked` · `429` per-IP limit.

No authentication: the handle only lets *that* hub push to *this* phone, which
is what the user asked for by signing in. Each call returns a different
handle for the same input; any of them works.

### `POST /v1/push` — send a notification (called by the hub)

`Authorization: Bearer <hub_token>`

```json
{
  "devices": ["prd_…", "prd_…"],
  "title": "api.example.com is down",
  "body": "HTTP 503 from 3 of 3 locations",
  "priority": "high",
  "thread_id": "monitor-42",
  "collapse_id": "monitor-42",
  "ttl": 3600,
  "silent": false,
  "data": {"type": "monitor", "monitor_id": "42", "status": "down"}
}
```

| Field | | |
|---|---|---|
| `devices` | required | 1 to 100 handles, no duplicates. More devices → more requests. |
| `title` | required | max 200 bytes |
| `body` | | max 2000 bytes |
| `priority` | `normal` | `high`: APNs priority 10 and `time-sensitive` (breaks through Focus). Use it for *down*. `normal`: priority 5. |
| `thread_id` | | Groups notifications on the phone (max 64 bytes) |
| `collapse_id` | | A newer notification with the same id replaces the old one (max 64 bytes) |
| `ttl` | FCM default (4 weeks) | Seconds APNs keeps trying when the phone is offline (0 to 2419200). An outage alert is stale after ~1 h. |
| `silent` | `false` | No sound |
| `data` | | String map for the app (deep links), max 16 keys and 2048 bytes. Keys `from`, `message_type`, `notification`, `google*`, `gcm*` are reserved. |

Answer `200` with one result per device, in the order sent:

```json
{"results": [
  {"device": "prd_…", "status": "sent"},
  {"device": "prd_…", "status": "gone", "error": "device no longer registered"}
]}
```

| Status | Hub should |
|---|---|
| `sent` | nothing |
| `gone` | **delete the device.** The app was removed, signed out, its FCM token changed, the handle is not for this hub, or the relay secret changed. The app enrolls again on its next start. |
| `rate_limited` | drop it (too many notifications to this phone) |
| `rejected` | drop it; FCM refused the message (log it) |
| `failed` | retry later with backoff (FCM unavailable or quota) |

Errors for the whole request: `400 invalid_request | invalid_json` ·
`401` · `403 hub_revoked` · `413` · `429` hub limit (`Retry-After`) ·
`503 fcm_not_configured`.

The relay does not retry and does not queue: the hub decides.

### `GET /healthz`

`200 {"status": "ok", "fcm": true}`. `fcm: false` means the relay runs without
Firebase credentials.

### `GET /`

`200 {"name": "pingtxt-push-relay", "version": "v0.1.0"}`

## Limits (defaults)

| | |
|---|---|
| per hub | 120 notifications/minute (one per device), bursts of 120 |
| per phone | 30/minute, bursts of 10 |
| per IP | 20 registrations + enrollments/minute, bursts of 10 |

## Hub side (pingtxt)

Built in pingtxt (migration 23, `internal/hub/apppush.go`). The routes are
under `/api/mobile/` because `/api/push/{token}` is taken by heartbeat monitors.

**Settings** (Settings → Mobile app, admin only, stored in the DB like the
other settings):

- `push.relay_url`, default `https://push.pingtxt.com`
- `push.hub_id` and `push.hub_token` (write-only, like the SMTP password):
  filled by the hub with `POST /v1/hubs` the first time the feature is turned
  on, or by a "Register" button. "Test" calls `GET /v1/hubs/me`.
- on/off switch.

**Table** `push_devices` (migration 23): `id`, `user_id`, `grant_id`,
`handle`, `name` ("Federico's iPhone"), `created_at`, `last_seen_at`. Unique on
`grant_id`: one handle per OAuth sign-in, a new one replaces it. Deleted with
the user, with the OAuth sign-in the app used (disconnect in "connected
apps", sign-out, expiry), and on a `gone` result.

**API for the app** (must work with the app's `pma_` OAuth tokens, also for
read-only users):

- `GET /api/mobile/config` → `{"enabled": true, "relay_url": "…", "hub_id": "…"}`
- `POST /api/mobile/devices` `{"device": "prd_…", "name": "iPhone"}` → upsert
  for the current sign-in, returns `{id}`. Only OAuth access tokens; `409`
  when push is off on the hub. The app sends it after every enrollment.
- `DELETE /api/mobile/devices/{id}` (app sign-out also revokes it).
- `GET /api/mobile/devices` → the user's devices (also listed in web settings).

**Sending**: notifier type `app` ("pingtxt app (push)") so the existing
routing, escalation and maintenance rules apply. Config `users`: emails, comma
separated (empty: all users). For each alert the hub collects the handles of those users, sends
batches of up to 100, and handles the results (`gone` → delete). Suggested
message:

- down: `priority: high`, `ttl: 3600`, `thread_id`/`collapse_id`:
  `monitor-<id>`, `data: {type: monitor, monitor_id, status: down}`
- up: `priority: normal`, same thread and collapse id (replaces the down
  notification on the lock screen)
- certificates, domains, incidents: `priority: normal`, `ttl: 86400`

Monitor names and error texts go through the relay in the message text but are
not stored there. Admins who do not want that can turn the feature off.

## App side (pingtxt-ios)

1. Firebase Messaging SDK, `GoogleService-Info.plist` of the relay's Firebase
   project, push capability, ask for notification permission (with
   *time-sensitive* entitlement for down alerts).
2. After sign-in, and in `messaging(_:didReceiveRegistrationToken:)`:
   `GET {hub}/api/mobile/config` → if enabled, `POST {relay_url}/v1/devices`
   with `hub_id` and the FCM token → `POST {hub}/api/mobile/devices`.
   Store the hub device id in the Keychain.
3. Sign-out: `DELETE {hub}/api/mobile/devices/{id}`, then revoke the OAuth
   token. With several hubs signed in, the same FCM token gets one handle per
   hub.
4. Tapping a notification: read `data.type` / `data.monitor_id` and open the
   monitor.

The FCM token never goes to the hub, only the handle.

## Security notes

- The relay keeps nothing: a leak of the server leaks only `RELAY_SECRET` and
  the Firebase key (rotate both, phones and hubs re-enroll).
- A hub token lets that hub push only to phones that enrolled with its hub id.
  Registration is open on the public relay because a fresh hub id has no
  phones; abuse is blocked with `RELAY_REVOKED_HUBS`.
- Someone who knows a phone's FCM token could enroll it with their own hub.
  FCM tokens are private to the app and its hub never sees them; per-phone
  limits cap the damage.
