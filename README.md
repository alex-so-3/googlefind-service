# googlefind

A small self-hosted HTTP service for the **Google Find Hub** devices of one Google account:
device list, decrypted location reports, on-demand locate, and the material needed to ring a
tracker over Bluetooth. Built on
[GoogleFindMyTools](https://github.com/leonboe1/GoogleFindMyTools) (GPL-3.0), which the Docker
image clones at a pinned commit.

It is the Google backend of [OpenTagViewer-triki](https://github.com/alex-so-3/OpenTagViewer-triki), a fork of
[OpenTagViewer](https://github.com/parawanderer/OpenTagViewer), and it keeps custom (DIY,
static-EID) trackers such as [find-my-triki](https://github.com/alex-so-3/find-my-triki) visible: Google forgets their EIDs
after about four days, so the service re-uploads them daily.

## How it works

- Google is asked for fresh locations **only on request** (`POST .../locate`). The answer comes
  back asynchronously over Firebase Cloud Messaging; the service keeps that connection open.
- Received reports are decrypted with the account's keys and stored in `data/reports.db`.
- Once a day (`REFRESH_INTERVAL_H`) the EIDs of custom trackers are re-uploaded.

## Setup

Signing in to Google needs a browser, so it is done once on a desktop with GoogleFindMyTools, and
the resulting tokens are copied to the service:

1. Clone GoogleFindMyTools, install its requirements and run `python main.py`. Sign in.
2. **Fetch one location** in that same run (pick any tracker). The first fetch opens a second
   browser step that retrieves your account's owner key; without it the service cannot decrypt
   anything. After this, `Auth/secrets.json` contains everything the service needs.
3. Copy `Auth/secrets.json` to `data/secrets.json` here and `chmod 600` it. Treat it like a
   password: it gives access to your devices' locations.
4. `cp .env.example .env` and set `API_TOKEN` to a long random string.
5. `docker compose up -d --build`, then check `curl localhost:8090/health`.
6. For access from outside your network, put it behind a reverse proxy with HTTPS and, preferably,
   HTTP Basic Auth. The service also accepts its token in `X-Api-Token`, so the proxy can use the
   `Authorization` header for Basic Auth.

If Google ever invalidates the tokens (`/health` shows errors), repeat steps 1–3 and restart.

To register a DIY tracker on the account, use GoogleFindMyTools' `main.py` → `r`; it prints the
EID to put into the tracker's firmware.

## Configuration

| Variable | Default | |
|---|---|---|
| `API_TOKEN` | – | required for `/api/*` (empty = no authentication; don't) |
| `REFRESH_INTERVAL_H` | `24` | how often custom tracker EIDs are re-uploaded |
| `LOG_LEVEL` | `INFO` | |

## API

All `/api/*` calls need the token (`Authorization: Bearer <token>` or `X-Api-Token: <token>`).

| Method | Path | |
|---|---|---|
| GET | `/health` | status: FCM connected, last refresh, last locate, last error (no token) |
| GET | `/api/devices` | devices: `id`, `name`, `custom`, `last_report` |
| GET | `/api/devices/{id}/reports?since=<unix s>&limit=` | decrypted reports, newest first |
| POST | `/api/devices/{id}/locate?wait=<s>` | ask Google now; with `wait` (≤ 60 s) block until the answer arrives |
| POST | `/api/refresh` | re-upload custom tracker EIDs now |
| GET | `/api/devices/{id}/ring` | `ring_key` and the tracker's current `eids`, for ringing it over Bluetooth |

The ring key can only make a tracker ring; it cannot decrypt locations.

## License

GPL-3.0, like GoogleFindMyTools, which this service imports.
