# SVA-ER/1 — Sovereign Verified Agency Execution Receipt Specification (v1.3)

- **Wire Spec Identifier:** `"sva-er/1"`
- **Media Type:** `application/sva-er+json`
- **Status:** Reference Draft (Sovereign Verified Agency Open Standards Suite)
- **Cryptographic Primitives:** `Ed25519` (RFC 8032), `SHA-256` (FIPS 180-4), `JCS` (RFC 8785), Domain-Separated Merkle Tree (RFC 6962), Timestamps (RFC 3339)
- **Wire Dependencies:** Zero proprietary encodings, zero external schemas, zero network calls required to verify.

> **Prior Art & Non-Collision Note:** This specification was originally drafted under the working label `AER/1` and renamed to **`SVA-ER/1`** (`application/sva-er+json`) to avoid colliding with the existing IETF Internet-Draft **`draft-zambo-aer1`** (*AER-1: A Portable Execution Receipt for AI Agent Tool Calls*, by Brennan Zambo). See [Section 7](#7-prior-art--comparison-with-ietf-draft-zambo-aer1-aer-1) for a factual comparison of the two distinct formats.

## 1. Purpose

A Sovereign Verified Agency Execution Receipt (`SVA-ER/1`) allows an independent verifier — holding only a JSON receipt and optionally the produced deliverable — to cryptographically prove:
1. Every included execution event is intact (hash recomputes over RFC 8785 JCS canonical form).
2. Every event was signed by the agency Ed25519 public key named in the receipt.
3. Every event is included in the agency's hash-chained ledger at its exact 1-based sequence index `seq` inside a tree of size `statement.size` (RFC 6962 `0x00`/`0x01` odd-node-promotion Merkle proof).
4. No inconvenient entries (such as `IN_CLOUD` inference or blocked egress leaks) were stripped or duplicated (`entries.length === statement.entries`, unique in-range `seq` values).
5. When a deliverable is supplied, it matches `statement.deliverableSha256` byte-for-byte; when omitted, the verifier explicitly reports `deliverable: "not_checked"` rather than silently collapsing it into a boolean pass.
6. Clock honesty is explicitly declared (`clock.status`: `attested`, `drift`, or `unattested`) and `clock.issuedAt` conforms strictly to RFC 3339 (valid calendar date including leap-year rules + explicit timezone).

## 2. Canonicalization (RFC 8785 JCS)

All JSON payloads hashed or signed MUST be serialized deterministically per RFC 8785:
- Object keys sorted lexicographically by UTF-16 code units, no insignificant whitespace.
- Undefined object properties omitted; `-0` normalized to `0`; numbers formatted per ECMAScript `Number.prototype.toString()`.
- Strings escaped per JSON (RFC 8259) minimal escaping.

## 3. RFC 6962 Merkle Tree (Domain-Separated, Promoted Odd Nodes)

Let `H(b)` be lowercase hex-encoded SHA-256 over raw bytes `b`:
- **Leaf hash:** `L(entryHashHex) = H(0x00 || UTF8(entryHashHex))`
- **Internal node hash:** `N(leftHex, rightHex) = H(0x01 || UTF8(leftHex) || UTF8(rightHex))`
- **Odd-node promotion:** If a level has an odd number of nodes, the trailing lone node is promoted unmodified to the next level (never duplicated — preventing CVE-2012-2459 tree-size collisions).

Given 1-based `seq` and ledger `size`, the expected proof step orientations `expectedSteps(seq, size)` are uniquely determined:
```text
idx = seq - 1; len = size; steps = []
while len > 1:
  if (idx % 2 == 0) and (idx + 1 == len):
    idx = idx >> 1; len = ceil(len / 2); continue
  steps.push(left = (idx % 2 == 1))
  idx = idx >> 1; len = ceil(len / 2)
```

## 4. Wire Format

```json
{
  "spec": "sva-er/1",
  "agency": { "name": "string", "publicKey": "<64-hex Ed25519 raw pubkey>" },
  "statement": {
    "type": "sva-er.statement",
    "missionId": "ms_...",
    "deliverableSha256": "<64-hex>",
    "merkleRoot": "<64-hex>",
    "merkle": "rfc6962-sha256",
    "size": 5,
    "entries": 3,
    "clock": { "status": "attested|drift|unattested", "issuedAt": "2026-11-26T00:00:00.000Z", "maxSkewSec": 300 }
  },
  "statementSig": "<128-hex Ed25519 signature over UTF8(JCS(statement))>",
  "entries": [
    {
      "seq": 1, "ts": "2026-11-26T00:00:00.000Z", "kind": "mission.create", "actor": "operator",
      "data": { "id": "ms_..." }, "prev": "<64-hex>",
      "hash": "<64-hex SHA-256(JCS({seq,ts,kind,actor,data,prev}))>",
      "sig": "<128-hex Ed25519 signature over UTF8(hash)>",
      "signer": "<64-hex == agency.publicKey>",
      "proof": [{ "hash": "<64-hex>", "left": false }]
    }
  ]
}
```

## 5. Verification Algorithm & Named Outcome Vocabulary (MUST FAIL CLOSED)

A conforming verifier MUST fail closed and MUST return a structured outcome object rather than collapsing distinct states into a single boolean:

```json
{
  "ok": true,
  "outcome": "verified | verification_failed | rejected_malformed",
  "deliverable": "verified | not_checked | verification_failed",
  "clock": "attested | drift | unattested | verification_failed"
}
```

Verification MUST reject (`ok: false`, `outcome: "rejected_malformed"` or `"verification_failed"`) unless ALL checks succeed:
1. `spec === "sva-er/1"`, `agency.publicKey` is 64 hex chars, `statement` is an object, `entries` is an array, `statement.type === "sva-er.statement"`, `statement.merkle === "rfc6962-sha256"`, `statement.size >= 1`, `statement.entries >= 1`.
2. `clock.status` is one of `"attested"`, `"drift"`, `"unattested"`, and `clock.issuedAt` is a valid **RFC 3339** timestamp (`YYYY-MM-DDTHH:MM:SS(.fraction)?(Z|[+-]HH:MM)`) with a real Gregorian calendar date (rejecting missing timezones and impossible dates such as `2026-02-29`).
3. `Ed25519Verify(agency.publicKey, UTF8(JCS(statement)), statementSig) === true`.
4. `entries.length === statement.entries`.
5. Every entry has unique integer `seq` with `1 <= seq <= statement.size`.
6. For every entry:
   - `SHA256(JCS({seq, ts, kind, actor, data, prev})) === entry.hash`.
   - `entry.signer === agency.publicKey` and `Ed25519Verify(agency.publicKey, UTF8(entry.hash), entry.sig) === true`.
   - `entry.proof.length === expectedSteps(entry.seq, statement.size).length`, every step `left` boolean matches `expectedSteps`, and folding `L(entry.hash)` via `N(...)` equals `statement.merkleRoot`.
   - Mission binding: `entry.data.id === statement.missionId || entry.data.missionId === statement.missionId`.
7. At least one entry has `kind === "mission.complete"` and `data.resultHash === statement.deliverableSha256`.
8. Deliverable handling:
   - If `deliverable` text is supplied: `SHA256(UTF8(deliverable)) === statement.deliverableSha256` (`deliverable: "verified"` on match, `"verification_failed"` on mismatch).
   - If `deliverable` is `null` / omitted: `deliverable: "not_checked"` (never falsely labeled `"verified"`).

## 6. Conformance

Verified across 3 independent zero-dependency implementations (`Node.js`, `Browser W3C WebCrypto`, `Single-File Pure Java 25`) in `conformance/v1/` (17 `svaer1` vectors including RFC 3339 timezone & leap-year regressions and named outcome assertions).

## 7. Prior Art & Comparison with IETF `draft-zambo-aer1` (AER-1)

`SVA-ER/1` is an independent format distinct from Brennan Zambo's IETF Internet-Draft **`draft-zambo-aer1`** (`AER-1`). Both formats fail closed, bind outputs by cryptographic digest, and detect entry tampering, stripping, and duplication, but they differ structurally on five axes (as established in a public 15-case comparison by `zambodotdev`):

| Axis | `SVA-ER/1` (this spec) | IETF `draft-zambo-aer1` (`AER-1`) |
|---|---|---|
| **Trust root** | Receipt is valid only under the Ed25519 key named in `agency.publicKey`. | Core receipt is keyless (recomputes canonical bytes); issuer identity is a separate attribution layer defaulting to `unverified`. |
| **Unit of record** | Single bundled JSON object containing a signed `statement` + mission `entries` subset + Merkle proofs. | Single execution receipt per tool call; sets are bound by separate commitment records. |
| **Merkle tree** | RFC 6962 `0x00`/`0x01` domain separation with **odd-node promotion** (eliminates CVE-2012-2459 structurally). | Odd-level last-node duplication with collision rejection at the layer above (`duplicate-receipt-id-collision`). |
| **Canonicalization** | RFC 8785 JCS. | AER-1 canonical byte serialization rules. |
| **Clock & Outcomes** | Explicit `clock.status` (`attested \| drift \| unattested`), strict RFC 3339 `clock.issuedAt`, and named verification outcomes (`deliverable: not_checked` when omitted). | Closed status/provenance vocabularies and explicit anchor outcomes (`verified`, `verification failed`, `rejected: unresolvable record`, `not checked`, `absent`). |
