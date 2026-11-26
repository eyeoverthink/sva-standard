# Joint Interop Vectors: `AER-1` (`draft-zambo-aer1-26`) ↔ `SVA-ER/1`

This directory implements the bidirectional clock-attestation and key-binding interop test harness proposed in [eyeoverthink/eyeoverthink-agency#7](https://github.com/eyeoverthink/eyeoverthink-agency/pull/7#issuecomment-7191779088) between **`SVA-ER/1`** (`eyeoverthink/sva-standard`) and **`AER-1`** (`draft-zambo-aer1-26`, kit `1.6.1`, evaluated set digest `sha256:4ea44dc07125a6f9b7fa472450a30fb56265771cfe87b1772a02b03d1fc166f2`).

## Design Principle

Each case expresses the **same execution event** in both `SVA-ER/1` and `AER-1` (`receipt_schema_version: "0.4"` with Section 3.1 `metadata_hash` and `issuer_claims` binding), with pinned expected outcomes for both verifiers:
- Fields `AER-1` core does not carry in-band (`clockAttestation`, `issuerKeyBinding`) explicitly read **`"absent"`** — never silently collapsed into a boolean pass or failure.
- `SVA-ER/1` directly evaluates `clock.status` (`attested | drift | unattested`), strict RFC 3339 `clock.issuedAt`, and Ed25519 key binding (`agency.publicKey`).

## Vector Matrix

| ID | Origin | What It Exercises | `SVA-ER/1` Expected | `AER-1` v0.4 Expected |
|---|---|---|---|---|
| `interop-01` | `svaer-04` | Valid execution with `clock.status = "unattested"` (`KEY_A`) | `verified`, `deliverable=verified`, `clock=unattested`, `keyBinding=verified` | `verified`, `clockAttestation=absent`, `issuerKeyBinding=absent` |
| `interop-02` | `svaer-05` | Valid execution with `clock.status = "drift"` under secondary `KEY_B` | `verified`, `deliverable=verified`, `clock=drift`, `keyBinding=verified` | `verified`, `clockAttestation=absent`, `issuerKeyBinding=absent` |
| `interop-03` | `svaer-05-key-swap` | Key-binding negative control (`KEY_B → KEY_A` swap in `SVA-ER/1`) + `created_at` tamper in `AER-1` (`metadata_hash` mismatch) | `verification_failed`, `keyBinding=verification_failed` | Core keyless record `verified` (`issuerKeyBinding=absent`); tampered `created_at` fails `metadata_hash` (`verification_failed`) |
| `interop-04` | `aer1:valid/bound-04.json` | Brennan's kit 1.6.1 `bound-04` (`get_weather`, Austin) expressed in `SVA-ER/1` | `verified`, `deliverable=verified`, `clock=attested`, `keyBinding=verified` | `verified`, `clockAttestation=absent`, `issuerKeyBinding=absent` |
| `interop-05` | `fmp1-offline-no-rtc` | Real hardware case: `FMP/1` Raspberry Pi mesh relay with no RTC (`clock_trusted=false`) delivering custodied message after partition | `verified`, `deliverable=verified`, `clock=unattested`, `keyBinding=verified` | `verified`, `clockAttestation=absent`, `issuerKeyBinding=absent` |
| `interop-06` | `aer1:aer-04` | AER-1-side authoring: `handover.wrap` execution with `clock.status = "unattested"` (`KEY_A`) | `verified`, `deliverable=verified`, `clock=unattested`, `keyBinding=verified` | `verified`, `clockAttestation=absent`, `issuerKeyBinding=absent` |
| `interop-07` | `aer1:aer-05` | AER-1-side authoring: `receipt.verify` execution with `clock.status = "drift"` under secondary `KEY_B` | `verified`, `deliverable=verified`, `clock=drift`, `keyBinding=verified` | `verified`, `clockAttestation=absent`, `issuerKeyBinding=absent` |

## Run Locally (0 deps, < 50 ms)

```bash
node conformance/interop/aer1-svaer1/generate-interop.mjs
node conformance/interop/aer1-svaer1/verify-interop.mjs
```
