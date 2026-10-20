# Deployment

## Configuration

Use `.env.example` as an inventory of settings, not a source of live secrets. The Go server reads process environment variables, not an automatic dotenv loader. `MASTER_KEY` and `ADMIN_TOKEN` are independent. Never bake either into an image, JavaScript, APK or Git history. PostgreSQL is optional, but a configured database must initialize successfully before listeners start.

For remote PostgreSQL, use a dedicated database/application role and verified TLS (`sslmode=verify-full` with the appropriate CA). Schema initialization needs table/index creation permissions. Local examples use `sslmode=disable` only for loopback/private development transport.

## HTTPS

HTTP defaults to `0.0.0.0:5000` and can be changed with `LISTEN_ADDR` or `-host`/`-port`. Set `HTTPS_ADDR` plus `TLS_CERT` and `TLS_KEY` to enable a second listener. HTTPS requires TLS 1.2+. The service validates the certificate and binds both ports before serving either endpoint.

```sh
export LISTEN_ADDR=127.0.0.1:5000
export HTTPS_ADDR=0.0.0.0:443
export TLS_CERT=/run/secrets/server-chain.pem
export TLS_KEY=/run/secrets/server-key.pem
./nfctag
```

Management APIs require HTTPS unless the immediate TCP peer is loopback. A TLS-terminating local reverse proxy can connect to loopback HTTP; forwarded HTTPS headers alone do not authorize plaintext management. Configure TLS or an appropriate local proxy topology in containers as well. Avoid Cloudflare Flexible mode for credentials traveling to an origin over plaintext.

`go run ./cmd/devcert -hosts localhost,127.0.0.1 -out .local-tls` creates a one-year self-signed **testing** certificate, refusing to overwrite files. It does not install trust. Public phones/browsers need a trusted certificate matching the tag URL's domain. Certificate keys must be readable by the runtime account and kept outside version control.

## Cloudflare and location

Set `CLOUDFLARE_PROXY=1` only for an origin receiving direct Cloudflare connections. `CF-Connecting-IP` is accepted only from the embedded published Cloudflare IPv4/IPv6 ranges; malformed/duplicate headers fall back to the peer IP. Pseudo IPv4 Overwrite mode uses a valid `CF-Connecting-IPv6` when appropriate. Keep `cloudflare-cidrs.txt` current and rebuild when Cloudflare changes ranges. A router/local proxy that rewrites source addresses requires explicit separate trust configuration.

For other proxies, `TRUSTED_PROXY_CIDRS` configures `X-Forwarded-For` trust. The chain is walked from the right until the first untrusted address. Do not trust the whole Internet or forward unvalidated client headers. Proxy headers describe network routing, not proof of user identity.

`IP_GEOLOCATION=1` opts into HTTPS queries to ipwho.is for public client IPs. Success is cached 24 hours, failures ten minutes; cache size is bounded. A 1.5-second timeout/rate limit leaves location unavailable. Local/loopback/carrier-NAT IPs are saved without external lookup. Third-party service terms and limits apply. Do not interpret these coordinates as GPS. Consider your notice/retention requirements before collecting visitor traffic data.

## Docker

`docker compose up -d postgres` starts only the local development database and binds it to loopback. Set `POSTGRES_PASSWORD` in `.env`; run the Go server on the host with matching environment variables.

Build the optional backend image with `docker build -t nfc-sdm-backend-go .`. It runs as UID/GID 65532, includes CA roots for optional HTTPS location queries and timezone data, and serves from `/app`. Supply runtime environment/secrets and a reachable database. For optional APK distribution, mount a file into `/app/dist/NFC-Tag-Writer-debug.apk` or set `APK_PATH`. Do not include the Android SDK or local credentials in the image build context. Container operation is not validated by the local Windows review when Docker is unavailable.

## Windows helpers

The optional PowerShell scripts use paths relative to this repository. For portable PostgreSQL, extract official Windows binaries into `.postgres-tools/pgsql`, then run `scripts/setup-postgres.ps1` once. It initializes a loopback-only database with random SCRAM credentials, restricts `local-secrets.json` to the current user and refuses to overwrite existing data. `scripts/start-postgres.ps1` preserves existing data. These helpers are development processes, not Windows services.

Set `MASTER_KEY`, optionally `DERIVE_MODE`, and run `scripts/start-backend.ps1` after `go build -o nfctag.exe .`. The helper reads database/admin credentials from ignored `local-secrets.json` and uses `.local-tls` for ports 80/443. It does not stop an existing application or save the NFC master. Cloudflare trust is off unless explicitly enabled in the environment. If local script policy blocks your own inspected scripts, a process-only `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...` is available without changing system policy.

## Operational limits and backups

Put request-size/rate limits and appropriate network access rules at the reverse proxy. Signature verification and append-only opening history are deliberately public operations; a valid replay can still create audit data. This software does not implement distributed rate limiting, multi-user accounts, a retention scheduler or physical-item ownership authentication.

Back up PostgreSQL with `pg_dump` and test restoration. Photos and events are in the database. Preserve the master and management secrets separately. Old backups, erased counter rows and rollbacks can permit previously rejected links. Never reset counters casually when rewriting tags; rollover/re-enrollment needs an explicit policy. Monitor database growth, disk availability, certificate expiry and failed starts. For production service lifecycle, use a service manager/container orchestrator rather than the development scripts.

Images are reencoded JPEG/PNG, at most 5 MiB and 12 megapixels, with a ten-photo-per-tag limit. Public photo URLs and directory data are intentionally accessible without management login. Do not upload private photographs or item fields to a public deployment.
