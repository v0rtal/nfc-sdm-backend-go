# NFC SDM Backend for Go

A self-hosted Go service for verifying **NXP NTAG 424 DNA and NTAG 424 DNA TagTamper** Secure Dynamic Messaging (SDM/SUN) URLs, recording verified link openings in PostgreSQL, and associating tags with item descriptions and photographs.

The companion [NFC Tag Writer for Android](https://github.com/v0rtal/nfc-tag-writer-android) provisions AES TagTamper tags. The two projects build independently. This service does not talk to an NFC reader or write tags.

## What it does

- Verifies encrypted AES and LRP tag messages, plaintext UID/counter messages, and supported bulk URLs against a configured master key.
- Supports the original upstream `legacy` derivation and its newer `standard` HMAC/AES-CMAC derivation. Writer and server must use the same master and mode.
- Decrypts and authenticates UID, read counter, supported encrypted file data and tamper status.
- Registers a tag only after its first signature-verified backend opening. PostgreSQL records every verified opening, its timestamp, validity decision and available traffic metadata.
- Atomically detects repeated links and older counters across concurrent requests and server instances. Every repeat is invalid immediately; the first opening has a 30-second display window.
- Preserves the first backend detection time of an authenticated tamper report; existing tamper history is backfilled during migration.
- Serves a public tag directory, item detail pages, photos, verification pages with badges, and the last ten verified openings on `/tagtt`.
- Provides password-protected item editing, image uploads/deletion and detailed scan history at `/admin`.
- Optionally records an approximate IP-based location and restores client IPs through explicitly trusted proxies or Cloudflare's published proxy ranges.
- Can serve HTTP and HTTPS simultaneously and optionally distribute the companion Android APK.

**These are tag-message verification and inventory features.** They do not independently authenticate an item's physical origin, prove ownership or implement ownership transfers. Chain of ownership is planned, not implemented.

## Quick start

Requires **Go 1.27.2 or newer** for the reviewed dependency/runtime baseline. PostgreSQL 17 or 18 is supported by the current schema; integration tests use PostgreSQL.

```sh
git clone https://github.com/v0rtal/nfc-sdm-backend-go.git
cd nfc-sdm-backend-go
go build -o nfctag .
./nfctag keygen
```

Save the generated NFC master securely. Generate a **different** secret for management access:

```sh
./nfctag keygen
export MASTER_KEY='YOUR_SAVED_NFC_MASTER_HEX'
export ADMIN_TOKEN='YOUR_SEPARATE_MANAGEMENT_SECRET'
export DERIVE_MODE=legacy
export DATABASE_URL='postgres://nfctag:YOUR_PASSWORD@127.0.0.1:5432/nfctag?sslmode=disable'
export LISTEN_ADDR=127.0.0.1:5000
./nfctag
```

PowerShell uses `$env:MASTER_KEY = '...'` instead of `export`. Open `http://127.0.0.1:5000/` and `/admin`. A master may be 16 or 32 hex-encoded bytes. The management secret must be at least 8 characters; use a randomly generated long secret for deployments. The server never returns its NFC master through an HTTP API.

For a local database, copy `.env.example` to `.env`, set a random `POSTGRES_PASSWORD`, and run `docker compose up -d postgres`. Set the matching `DATABASE_URL` in the server's environment. **Go does not automatically read `.env`**; Compose reads it only for the database. See [deployment](docs/DEPLOYMENT.md) for Docker, Windows helpers, TLS and backups.

Omitting `DATABASE_URL` runs cryptographic verification without inventory/replay protection. Responses explicitly indicate that freshness tracking is disabled. `MASTER_KEY` is always required. Factory-key tests additionally require `ALLOW_FACTORY_KEYS=1`; that is not a deployment configuration.

## Routes

| Route                                  | Behavior                                                                       |
| -------------------------------------- | ------------------------------------------------------------------------------ |
| `/`                                    | Public directory: UID, name and first ten description words; 24 items per page |
| `/items/UID`                           | Public registered item details, photos and recorded statistics                 |
| `/tag`, `/tagtt`, `/tagpt`             | Browser verification for encrypted, TagTamper and plaintext layouts            |
| `/api/tag`, `/api/tagtt`, `/api/tagpt` | Equivalent JSON verification; check `link_valid`, not just HTTP 200            |
| `/admin`                               | Management page; APIs require the separate bearer password                     |
| `/api/admin/tags`                      | List registered tags; supports `offset`                                        |
| `/api/admin/tags/UID`                  | `GET` details; `PUT` name, description and JSON attributes                     |
| `/api/admin/tags/UID/history`          | Last ten openings, including IP/location when recorded                         |
| `/api/admin/tags/UID/images`           | `POST` raw JPEG/PNG, up to 5 MiB and 12 megapixels                             |
| `/api/admin/tags/UID/images/IMAGE_ID`  | `DELETE` a photo; at most ten photos per tag                                   |
| `/images/IMAGE_ID`                     | Public photo bytes                                                             |
| `/downloads/NFC-Tag-Writer-debug.apk`  | Optional APK download from `APK_PATH`                                          |
| `/webnfc`                              | Browser NDEF reading helper; HTTPS/browser support required                    |
| `/healthz`                             | Health, including PostgreSQL connectivity when configured                      |

Successful JSON verification includes `signature_valid`, UID, read counter, encryption mode, `tracking_enabled`, `link_valid`, a validity status/timestamps and the item's public data. Encrypted routes also include `file_data` and `tt_status`. See [protocol and API](docs/PROTOCOL.md).

## Keys and tag writing

```sh
./nfctag derive 04112233445566
./nfctag ndef -url https://example.com/tag
```

`derive` prints **secret per-tag keys 0–4** locally; do not paste the output into public logs. Key 1 is not UID-diversified because it must decrypt PICC data before the UID is known. The `ndef` helper emits the unencrypted-file `/tag` layout, not the Android app's encrypted-file TagTamper layout. The Android app computes its own `/tagtt` file and offsets.

## Important limits

- A tag URL has a counter, **not a trusted scan timestamp**. Thirty seconds starts when this backend records a first opening. A never-submitted saved higher-counter URL may still be accepted later.
- Reopening, previewing or prefetching a link consumes its first opening. A valid signature and a fresh link are separate results. Browser badges labeled Authentic/Counterfeit describe verification against this backend key, not an independent forensic determination about the item.
- Tamper detection timestamps record backend observation, not the moment the physical loop opened. An open loop can record a permanent tamper history even if closed again.
- Public item information/photos, directory statistics and `/tagtt` history are intentionally public. IP/location remain in authenticated management history. Public directory browsing creates no scan event.
- Location is approximate network-exit information, not GPS. `IP_GEOLOCATION=1` sends a public client IP to **ipwho.is**. It is disabled by default in this public distribution.
- Counter resets/rollover are treated as stale. Restoring old database backups or deleting scan records weakens replay protection. No automatic history-retention job or multi-user ownership system is implemented.
- This is reviewed development software, not a certified security product. Cryptographic vectors and card simulations do not replace physical tag, RF and deployment testing.

## Development

```sh
go test ./...
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Set `TEST_DATABASE_URL` to a disposable PostgreSQL database for integration tests. Tests use isolated schemas and cover simultaneous first openings, replay policy, tamper timestamps/backfill, item/image APIs, HTML escaping and trusted proxy handling. See [architecture](docs/ARCHITECTURE.md), [security](SECURITY.md), [review notes](REVIEW.md), and [contributing](CONTRIBUTING.md).

## Attribution and license

MIT licensed. This project began as a Go port of [nfc-developer/sdm-backend](https://github.com/nfc-developer/sdm-backend), baseline commit `37585f0c76eded73798b936b17aa5e187075b78f`. Original copyright and license notices are preserved. See [NOTICE](NOTICE.md). NXP's datasheets and application notes define the tag protocol; this project is not affiliated with NXP.
