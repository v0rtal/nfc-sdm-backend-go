# Architecture

## Request flow

Verification is deliberately ordered: bound/parse URL input, validate configuration, verify/decrypt the SDM cryptogram, resolve optional traffic metadata, record the verified opening transactionally, then render public data. Invalid signatures never create inventory rows. A configured database failure produces 503 rather than a fresh-link claim.

`main.go` owns configuration, verification endpoints, the embedded public result template, optional APK delivery and HTTP/TLS startup. `directory.go` renders a paginated public projection; it never consumes tag links or writes scan history. `management.go` protects editing/history with a separate bearer secret, handles bounded image uploads and defines public status projections. `traffic.go` handles peer/forwarded IP trust and optional external location lookup.

`sdm/` contains the binary protocol and AES/LRP cryptography. The verifier checks lengths and configuration before low-level AES operations, derives session keys from authenticated PICC data, verifies CMAC in constant time and only then accepts decrypted data. Cryptographic behavior is checked against upstream/NXP vectors and the Android-generated interoperability fixture.

## PostgreSQL state

`inventory/schema.sql` initializes/upgrades schema versions 1–3 inside an advisory-locked transaction. It does not create or drop the configured database.

- `tags`: UID, editable item data, highest observed read counter, counts, latest recorded state and first tamper detection.
- `scans`: one immutable first receipt/expiry per `(UID,counter)`, plus opening count.
- `scan_events`: every verified opening and its validity, timestamp, tamper report, IP and optional approximate location.
- `item_images`: reencoded JPEG/PNG bytes and random image IDs.

`Store.ObserveTraffic` locks the tag row (`FOR UPDATE`) before comparing/updating counters and creating the counter record. Concurrent first openings serialize per UID, so only one is accepted. Lower counters never roll back the high-water mark. An old authenticated tamper report can still establish the first observed tamper time; it cannot overwrite a newer current tamper status. Timestamps use the database clock, and expiry is 30 seconds after its recorded first receipt.

## Privacy boundaries

Public item pages, images and directory details are public by design. `/tagtt` gets an explicit projection of history that omits IP/location. Management history requires authentication and includes those fields. The master is not stored in the database, and raw tag URLs are not logged as events. Optional IP lookup sends only an IP to the provider; it never forwards tag URLs or keys.

## Repository boundary

The backend builds without an Android checkout, SDK or Java. Its Android fixtures are published nonsecret test inputs. APK distribution reads the single operator-configured `APK_PATH`; the companion repository owns Android source and build/signing. No live deployment credentials, database data, TLS keys, APKs or local toolchains are shipped in source control.
