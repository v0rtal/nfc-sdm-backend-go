# Source review and repository split

Reviewed October 20, 2026. This is an engineering review and regression-test baseline, not an independent penetration test, cryptographic certification or physical tag/RF audit.

## Scope

Reviewed HTTP input/response handling, verification order, key configuration, AES/LRP compatibility, counter transactions, tamper history, public/private data boundaries, proxy trust, image handling, templates, local setup scripts, container packaging, dependencies and repository contents. The companion Android source has a separate review record.

## Changes made during review

| Finding                                                                               | Resolution                                                                                                             |
| ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| A missing master silently selected known factory keys                                 | Require `MASTER_KEY`; factory-key startup additionally requires `ALLOW_FACTORY_KEYS=1`                                 |
| Bad verifier configuration could reach panicking AES primitives through library calls | Validate master length and derivation mode at both public verification entry points                                    |
| Older PostgreSQL/text dependencies and Go runtime had reported advisories             | Upgrade pgx, transitive crypto/text dependencies and require the patched Go 1.27.2 baseline; rerun govulncheck         |
| APK path and footer assumed a sibling Android tree and one deployment domain          | Configurable `APK_PATH`, relative download URL, independent source/build boundaries                                    |
| Third-party geolocation was enabled implicitly                                        | Make public-IP lookup opt-in; document disclosure and proxy trust                                                      |
| Integration fixtures could clean up rows in a caller's default schema                 | Give HTTP and storage integration tests isolated schemas                                                               |
| Scratch runtime lacked CA roots for HTTPS location lookup                             | Use a minimal non-root runtime with CA certificates/timezone data                                                      |
| Dense source/templates and deployment-specific documentation                          | Apply standard Go/Java/template formatting; replace docs with portable setup, API, architecture and scope descriptions |
| Labels could show a non-UTC timestamp with a literal UTC suffix                       | Explicitly convert labeled verification timestamps to UTC                                                              |

Important existing invariants were retained: signature verification precedes persistence; per-UID row locking serializes first openings; duplicate links do not renew expiry; stale counters never lower the high-water mark; first tamper detection persists; management/IP data is not projected into public scan history; images are bounded and reencoded.

## Validation baseline

The release preparation runs Go tests, PostgreSQL integration tests against a separate test database, vet, build, and the official Go vulnerability checker with the patched toolchain. Regression tests cover explicit master/factory opt-in, invalid library configuration, standalone APK delivery and the preserved transactional/security behavior. Exact command outcomes are reported with the repository publication; CI repeats tests/vet/build on later changes.

## Remaining limits

- No trusted physical scan clock, proof of item origin/ownership, ownership transfer flow, or counter reset/re-enrollment workflow.
- Browser previews consume links under the intentional strict first-open policy.
- Public directory/item data and photo URLs are public. Public tag pages show the last ten verified openings but no IP/location.
- Optional IP geolocation uses a third party; address-derived location is not precise phone location. Cloudflare ranges need maintenance.
- A single bearer password controls management. No user roles, distributed rate limiter, audit retention scheduler or automatic certificate renewal.
- A valid link can be replayed to append audit data. Put deployment-specific rate limits at the proxy and monitor disk growth.
- Database rollback/restore and master-key compromise have security consequences. Production backup and key rotation procedures are operator responsibilities.
- Physical interoperability, production packaging, certificate trust and image/container scanning require deployment-specific acceptance tests. Docker is not assumed to be available on the Windows review machine.

No deployment secrets, live database contents, private TLS keys, local SDK/JDK tools, APKs or debug signing keys are included in this repository. Public fixture masters are deterministic test data and must never be reused in deployment.
