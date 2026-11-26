# POR/1 — Proof-of-Reality Local-Hash Vault Profile (v1.0)

- **Wire Spec Identifier:** `"por/1"`
- **Media Type:** `application/por+json`
- **Status:** Reference Draft (Sovereign Verified Agency Open Standards Suite)
- **Cryptographic Primitives:** `Ed25519` (RFC 8032), `SHA-256` (FIPS 180-4), `JCS` (RFC 8785), Domain-Separated Merkle Tree (RFC 6962 `0x00`/`0x01` odd-node promotion)

## 1. Purpose

`POR/1` provides a privacy-preserving, offline-verifiable attestation profile for multi-modal capture records (such as local biometric, sensor, location, and timestamp witnesses) built on the **exact same RFC 6962 Merkle tree and Ed25519 primitives as `SVA-ER/1`**.

Crucial privacy invariant: **raw biometrics and sensitive captures MUST NEVER enter the wire vault**. Only lowercase 64-hex `SHA-256` digests of each local field appear in `leaves`. Changing a single byte of any underlying capture changes its leaf digest, invalidates its Merkle inclusion proof, and changes the signed root.

## 2. RFC 6962 Merkle Alignment with `SVA-ER/1`

Every leaf `leaves[i]` is a 64-character lowercase hex SHA-256 digest of the local field bytes:
- **Leaf hash:** `L(leafHex) = SHA-256(0x00 || UTF8(leafHex))`
- **Internal node:** `N(leftHex, rightHex) = SHA-256(0x01 || UTF8(leftHex) || UTF8(rightHex))`
- **Odd-node promotion:** Trailing lone nodes at any level are promoted unmodified (never duplicated).

## 3. Wire Format (`por/1`)

```json
{
  "spec": "por/1",
  "agentId": "fx-xxxx-xxxx-xxxx-xxxx",
  "publicKey": "<64-hex Ed25519 raw pubkey>",
  "issuedAt": "2026-11-26T00:00:00.000Z",
  "fields": ["face", "voice", "geo", "xyz", "wrgba", "time", "pub"],
  "leaves": ["<64-hex>", "..."],
  "merkle": "rfc6962-sha256",
  "root": "<64-hex Merkle root over leaves>",
  "sig": "<128-hex Ed25519 signature over UTF8(JCS(vault without sig))>"
}
```

Where `agentId` is deterministically derived from `publicKey` (following FRAYMUS v13 addressing):
`agentId = "fx-" + chunk4(SHA-256(rawPublicKeyBytes).hex.slice(0, 16))` (e.g. `fx-d75a-9801-82b1-0ab7`).

## 4. Mandatory Verification Rules (MUST FAIL CLOSED)

1. `spec === "por/1"`, `merkle === "rfc6962-sha256"`, `publicKey` is 64 hex chars, `sig` is 128 hex chars, `issuedAt` is valid RFC 3339.
2. `agentId` equals `"fx-" + SHA-256(rawBytes(publicKey)).hex[0..16]` hyphenated every 4 hex characters.
3. `fields` and `leaves` are non-empty arrays of identical length (`>= 1`); every `fields[i]` is a non-empty string and every `leaves[i]` is strictly a 64-char lowercase hex string (rejecting raw unhashed data fail-closed).
4. Recomputing the RFC 6962 Merkle root over `leaves` equals `root`.
5. `Ed25519Verify(publicKey, UTF8(JCS(vault without sig)), sig) === true`.
6. If an optional selective-disclosure inclusion proof `{ fieldIndex, leafHex, path }` is supplied, `leafHex === leaves[fieldIndex]` and `verifyMerkle({ leaf: leafHex, seq: fieldIndex + 1, size: leaves.length, root, path }) === true`.
