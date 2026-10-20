# Security

Use high-entropy, unique NFC masters and a separate management secret. Never publish keys, per-tag derivation output, raw live signed URLs, database credentials or TLS private keys in issues. Treat public test-vector keys as compromised by definition. A repository review is not a security certification.

The documented security boundaries are message signature verification, counter/replay tracking and authenticated management APIs. They do not prove physical-item origin, user identity, ownership or a scan time for a never-submitted URL. Read the limits in README and docs/PROTOCOL.md before using verification to authorize valuable actions.

Deploy behind appropriate TLS and rate limiting, keep runtime/dependencies patched, maintain trusted proxy lists, monitor history growth and test backups. Item data/photos and some scan history are public by design. Optional external IP lookup is opt-in and approximate.

For sensitive vulnerability reports, use GitHub private vulnerability reporting if enabled for this repository. Otherwise request a private reporting channel without including exploit details or secrets in a public issue. No response-time or supported-release SLA is promised.
