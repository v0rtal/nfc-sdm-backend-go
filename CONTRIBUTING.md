# Contributing

Use Go 1.27.2 or newer, format with gofmt/goimports, and run tests/vet before opening a change. Set `TEST_DATABASE_URL` to a dedicated disposable PostgreSQL database to run integration tests. Tests use isolated schemas; do not rely on production databases for development.

Keep signature verification before persistence, counter updates transactional, replay timestamps immutable, and public history free of client IP/location. Add meaningful known-answer or failure-path tests for cryptographic/protocol changes. Preserve the Go/Android fixture contract when changing NDEF layout or derivation. Do not change UI labels into claims of ownership or physical item authenticity.

Web templates use Prettier with prettier-plugin-go-template. Formatting tools are development dependencies only; they are not required by the Go runtime. Explain API/schema changes and provide migrations without erasing history. Do not commit environment files, credentials, per-tag live vectors, APKs, database data or TLS keys.

Use issues for nonsensitive bugs and SECURITY.md for sensitive reports. Include reproduction steps, expected/actual behavior and relevant redacted test results. No ownership-transfer, billing or hardware-security promises should be added without implementation and acceptance tests.
