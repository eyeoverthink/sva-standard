# EMA/1 — Egress Membrane Attestation Specification (v1.0 Draft)

- **Media Type:** `application/ema+json`
- **Status:** Reference Draft (Sovereign Verified Agency Open Standards Suite)
- **Cryptographic Primitives:** `Ed25519` (RFC 8032), `SHA-256`, `HMAC-SHA256` (RFC 2104), `JCS` (RFC 8785)

## 1. Purpose

`EMA/1` proves what crossed an AI runtime's network boundary — or proves that **nothing crossed at all** (`mode: "ONLY_ON_DEVICE"` / airgap attestation) — without logging plaintext private values.

## 2. Placeholder Grammar & Digit-Squeezed Leak Audit

- Sealed values are replaced with typed placeholders `⟦TYPE_N⟧` (U+27E6 / U+27E7).
- Before egress, a runtime MUST run a hard **egress audit** over the serialized outbound payload `P`:
  - No original withheld value `v` may occur in `P` (case-insensitive substring match).
  - For any `v` containing 7 or more decimal digits, `digitsOnly(v)` (and its last 10 digits if `len > 10`) MUST NOT occur in `squeezeDigits(P)` (where `squeezeDigits` removes whitespace, dashes, dots, and parentheses between adjacent digits).
- Each withheld value is logged only as a keyed correlation tag: `HMAC-SHA256(localSecretKeyHex, UTF8(value.toLowerCase())).slice(0, 16)` (16 lowercase hex chars). This lets auditors correlate repeat withholding across crossings without exposing plaintext.

## 3. Wire Format (`ema/1`)

```json
{
  "spec": "ema/1",
  "mode": "SEALED_EGRESS | ONLY_ON_DEVICE",
  "provider": "firebase-edge | local-ollama",
  "model": "gemini-2.5-flash",
  "outboundSha256": "<64-hex SHA-256 of outbound payload, or SHA-256('') for ONLY_ON_DEVICE>",
  "egressBytes": 142,
  "withheld": { "EMAIL": 1, "SSN": 1 },
  "totalWithheld": 2,
  "tags": [
    { "type": "EMAIL", "tag": "<16-hex HMAC-SHA256 prefix>" },
    { "type": "SSN", "tag": "<16-hex HMAC-SHA256 prefix>" }
  ],
  "audit": "clean",
  "strictNer": true,
  "airgap": { "networkInterfaces": 0, "verified": true },
  "issuedAt": "2026-11-26T00:00:00.000Z",
  "signer": "<64-hex Ed25519 raw pubkey>",
  "sig": "<128-hex Ed25519 signature over UTF8(JCS(attestation without sig))>"
}
```

## 4. Mandatory Verification Checks (Fail Closed)

1. `spec === "ema/1"`, `mode` is `"SEALED_EGRESS"` or `"ONLY_ON_DEVICE"`, `audit === "clean"`.
2. `outboundSha256` is 64 hex chars, `egressBytes` is a non-negative integer.
3. Sum of `withheld` counts equals `totalWithheld` and equals `tags.length`; every tag has a 16-hex lowercase `tag`.
4. If `mode === "ONLY_ON_DEVICE"`: `egressBytes === 0`, `outboundSha256 === SHA256("")` (`e3b0c442...`), and if `airgap` is present, `airgap.networkInterfaces === 0 && airgap.verified === true`.
5. `signer` is 64 hex chars, `sig` is 128 hex chars, and `Ed25519Verify(signer, UTF8(JCS(attestation without sig)), sig) === true`.
6. **Optional Payload & Key Audit (when verifier holds `outboundPayload` and/or local `hmacKeyHex` + `originalValues`):**
   - `SHA256(UTF8(outboundPayload)) === outboundSha256` and `UTF8(outboundPayload).length === egressBytes`.
   - Every `originalValue` passes both raw case-insensitive and digit-squeezed leak checks against `outboundPayload`.
   - Every `HMAC-SHA256(hmacKeyHex, UTF8(v.toLowerCase())).slice(0, 16)` matches the corresponding attested `tags[i].tag`.
