# Protocol and validity API

The server verifies NTAG 424 DNA SDM/SUN data. It supports AES PICC blocks, LRP PICC messages, optional block-aligned encrypted file content, upstream bulk `e` layouts and plaintext UID/counter/CMAC URLs. `REQUIRE_LRP=1` refuses AES/plaintext verification; the Android companion only provisions AES.

Default query names are `picc_data`, `enc`, `cmac`, `uid`, `ctr`, and bulk `e`. Rename supported fields with `ENC_PICC_DATA_PARAM`, `ENC_FILE_DATA_PARAM`, `SDMMAC_PARAM`, `UID_PARAM` and `CTR_PARAM`. These names affect MAC input; the Android companion uses the fixed defaults. A bulk message carries its own concatenated PICC/file/MAC data. Duplicate cryptographic parameters and invalid hexadecimal lengths are rejected. URL query size is limited to 4 KiB.

## Key derivation

`legacy` implements upstream PBKDF2-HMAC-SHA512 with 5,000 rounds, a binary master and role/UID-dependent salts. `standard` implements upstream HMAC-SHA256/AES-CMAC diversification with separate slot/diversification inputs. Key 1 is independent of UID in the companion layout; file key 2 is UID-diversified. Switching modes without rewriting the tag changes its expected keys and breaks verification.

The exact all-zero 16-byte master selects upstream's factory-key shortcut, but standalone server startup requires explicit `ALLOW_FACTORY_KEYS=1` for it. The shortcut is for known factory test vectors, not deployed tag security. Both normal master lengths derive 128-bit AES tag keys.

## JSON verification

```json
{
  "signature_valid": true,
  "uid": "04112233445566",
  "read_ctr": 123,
  "enc_mode": "AES",
  "tracking_enabled": true,
  "link_valid": false,
  "link_validity": {
    "valid": false,
    "status": "replayed",
    "repeat": true,
    "latest_counter": 123
  }
}
```

The real response also contains the recorded observation/first-seen/expiry timestamps, public item data and applicable file/tamper fields. Times are RFC 3339. Status values are:

| Status            | Meaning                                                              |
| ----------------- | -------------------------------------------------------------------- |
| `fresh`           | First recorded opening of a non-regressing counter                   |
| `replayed`        | That counter was already opened, even within 30 seconds              |
| `expired`         | The first-opening window has ended                                   |
| `stale`           | A higher counter is already known; this includes unseen old counters |
| `counter_missing` | Signature valid but no counter is available for freshness            |

Precedence is missing counter, stale, expired, replayed, fresh. HTTP 200 means cryptographic verification succeeded; use `link_valid` to decide freshness. Invalid input/signatures return 400, and configured tracking failures return 503. With no database, responses mark tracking disabled and never assert link freshness.

Tamper values include `secure` (CC), `tampered_closed` (OC), `tampered_open` (OO), `not_initialized` (II), `not_supported` (NT) and `unknown`. `tamper_detected_at` is the earliest backend receipt of a verified tampered report. It is not a tag-clock timestamp. The public UI's signature badge remains separate from replay validity and tamper state.

## Scope of freshness

A signature authenticates a generated message under a key. It does not date a URL that has never reached the server. Counter gaps can result from offline reads. Previews/prefetch and an attacker opening a captured link first can consume a first opening. Existing open pages update their local expiration banner but do not poll for later counters. Protecting a single-use transaction may require a different, interactive protocol.

References: [NXP datasheet](https://www.nxp.com/docs/en/data-sheet/NT4H2421Tx.pdf), [AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf), and the [upstream backend](https://github.com/nfc-developer/sdm-backend).
