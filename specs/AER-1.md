# AER/1 — Agent Execution Receipt Specification (v1.0 Draft)

- **Media Type:** `application/aer+json`
- **Status:** Reference Draft (Sovereign Verified Agency Open Standards Suite)
- **Cryptographic Primitives:** `Ed25519` (RFC 8032), `SHA-256` (FIPS 180-4), `JCS` (RFC 8785), Domain-Separated Merkle Tree (RFC 6962)
- **Wire Dependencies:** Zero proprietary encodings, zero external schemas, zero network calls required to verify.

## 1. Purpose

An Agent Execution Receipt (`AER/1`) allows an independent verifier — holding only a JSON receipt and optionally the produced deliverable — to cryptographically prove:
1. Every included execution event is intact (hash recomputes over JCS canonical form).
2. Every event was signed by the agency public key named in the receipt.
3. Every event is included in the agency's hash-chained ledger at its exact 1-based sequence index `seq` inside a tree of size `statement.size` (RFC 6962 Merkle proof).
4. No inconvenient entries (such as cloud egress or blocked leaks) were stripped or duplicated (`entries.length === statement.entries`, unique `seq` values).
5. The deliverable held by the verifier matches `statement.deliverableSha256` byte-for-byte.
6. Clock honesty is explicitly declared (`clock.status`: `attested`, `drift`, or `unattested`) rather than silently trusted.

## 2. Canonicalization (RFC 8785 JCS)

All JSON payloads hashed or signed MUST be serialized deterministically:
- Object keys sorted lexicographically by UTF-16 code units, no insignificant whitespace.
- Undefined object properties omitted; `-0` normalized to `0`.
- Strings escaped per JSON (RFC 8259) minimal escaping.

## 3. RFC 6962 Merkle Tree (Domain-Separated, Promoted Odd Nodes)

Let $H(b)$ be lowercase hex-encoded SHA-256 over raw bytes $b$:
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
  "spec": "aer/1",
  "agency": { "name": "string", "publicKey": "<64-hex Ed25519 raw pubkey>" },
  "statement": {
    "type": "aer.statement",
    "missionId": "ms_...",
    "deliverableSha256": "<64-hex>",
    "merkleRoot": "<64-hex>",
    "merkle": "rfc6962-sha256",
    "size": 5,
    "entries": 3,
    "clock": { "status": "attested|drift|unattested", "issuedAt": "ISO-8601", "maxSkewSec": 300 }
  },
  "statementSig": "<128-hex Ed25519 signature over UTF8(JCS(statement))>",
  "entries": [
    {
      "seq": 1, "ts": "ISO-8601", "kind": "mission.create", "actor": "operator",
      "data": { "id": "ms_..." }, "prev": "<64-hex>",
      "hash": "<64-hex SHA-256(JCS({seq,ts,kind,actor,data,prev}))>",
      "sig": "<128-hex Ed25519 signature over UTF8(hash)>",
      "signer": "<64-hex == agency.publicKey>",
      "proof": [{ "hash": "<64-hex>", "left": false }]
    }
  ]
}
```

## 5. Verification Algorithm (MUST FAIL CLOSED)

A conforming verifier MUST reject unless ALL checks succeed:
1. `spec === "aer/1"`, `agency.publicKey` is 64 hex chars, `statement` is an object, `entries` is an array, `statement.merkle === "rfc6962-sha256"`, `statement.size >= 1`, `statement.entries >= 1`.
2. `clock.status` is one of `"attested"`, `"drift"`, `"unattested"` and `clock.issuedAt` is a non-empty string.
3. `Ed25519Verify(agency.publicKey, UTF8(JCS(statement)), statementSig) === true`.
4. `entries.length === statement.entries`.
5. Every entry has unique integer `seq` with `1 <= seq <= statement.size`.
6. For every entry:
   - `SHA256(JCS({seq, ts, kind, actor, data, prev})) === entry.hash`.
   - `entry.signer === agency.publicKey` and `Ed25519Verify(agency.publicKey, UTF8(entry.hash), entry.sig) === true`.
   - `entry.proof.length === expectedSteps(entry.seq, statement.size).length`, every step `left` boolean matches `expectedSteps`, and folding `L(entry.hash)` via `N(...)` equals `statement.merkleRoot`.
   - Mission binding: `entry.data.id === statement.missionId || entry.data.missionId === statement.missionId`.
7. At least one entry has `kind === "mission.complete"` and `data.resultHash === statement.deliverableSha256`.
8. If `deliverable` text is supplied, `SHA256(UTF8(deliverable)) === statement.deliverableSha256`.

## 6. Conformance

Verified across 3 independent zero-dependency implementations (`Node.js`, `Browser W3C WebCrypto`, `Single-File Java 25`) in `conformance/v1/`.
