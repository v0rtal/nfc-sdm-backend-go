# Attribution

The original upstream SDM backend is [nfc-developer/sdm-backend](https://github.com/nfc-developer/sdm-backend), baseline commit `37585f0c76eded73798b936b17aa5e187075b78f`, MIT licensed. Its original copyright/license text is retained in LICENSE. This Go project adds its own implementation and inventory/management functionality.

NXP's NTAG 424 DNA / TagTamper datasheets and AN12196 describe the protocol and examples used in interoperability tests. NXP and NTAG names identify compatible hardware; no affiliation or endorsement is implied.

Go dependencies retain their own licenses through their upstream modules. In particular, pgx provides PostgreSQL connectivity. No third-party deployment credential, source checkout or local runtime artifact is vendored here.
