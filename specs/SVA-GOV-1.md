# SVA-GOV/1 — Signed Operator Autonomy Stone & Task Witness Governance (v1.0)

- **Wire Spec Identifiers:** `"sva-gov-stone/1"`, `"sva-gov-task/1"`
- **Media Type:** `application/sva-gov+json`
- **Status:** Reference Draft (Sovereign Verified Agency Open Standards Suite)
- **Cryptographic Primitives:** `Ed25519` (RFC 8032), `SHA-256` (FIPS 180-4), `JCS` (RFC 8785), Timestamps (RFC 3339)

## 1. Purpose

Multi-agent fleets coordinating across heterogeneous hosts (laptops, local GPU workstations, VPS nodes) via Git or HTTP buses need a **cryptographically enforceable autonomy kill-switch** and a **human-traceable task authorization trail** — not an unsigned prose manifesto that any daemon with push access can edit.

`SVA-GOV/1` turns a Git-tracked policy file (`OWNER_STONE`) and task queue (`task_queue`) into fail-closed, Ed25519-verifiable records:
1. Only the holder of `ownerPublicKey` can mint, scope, pause, or revoke an autonomy grant.
2. Every daemon MUST verify the signed Policy Stone before claiming or executing any task — if `status` is `"PAUSED"` or `"REVOKED"`, execution halts immediately.
3. Every queued or completed task MUST carry an `operatorAuthorizationRef` and `witnessReceiptSha256` binding it to a human-visible witness record and an enrolled logical `agent` ID (never raw host IPs or tokens).

## 2. Wire Format

### 2.1 Policy Stone (`sva-gov-stone/1`)

```json
{
  "spec": "sva-gov-stone/1",
  "ownerId": "fx-xxxx-xxxx-xxxx-xxxx",
  "ownerPublicKey": "<64-hex Ed25519 raw pubkey>",
  "grantId": "grant_2026_11_26_scoped",
  "status": "ACTIVE | SCOPED | PAUSED | REVOKED",
  "allowedAgents": ["mac-hermes", "assay-01"],
  "issuedAt": "2026-11-26T00:00:00.000Z",
  "sig": "<128-hex Ed25519 signature over UTF8(JCS(stone without sig))>"
}
```

### 2.2 Task Claim (`sva-gov-task/1`)

```json
{
  "spec": "sva-gov-task/1",
  "taskId": "task-001",
  "agent": "mac-hermes",
  "grantId": "grant_2026_11_26_scoped",
  "operatorAuthorizationRef": "witness_ledger.jsonl#entry_01",
  "witnessReceiptSha256": "<64-hex>",
  "issuedAt": "2026-11-26T00:00:00.000Z"
}
```

## 3. Mandatory Admission Rules (MUST FAIL CLOSED)

A daemon or verifier evaluating `{ stone, task }` MUST reject unless ALL checks succeed:
1. `stone.spec === "sva-gov-stone/1"`, `stone.ownerPublicKey` is 64 hex chars, `stone.sig` is 128 hex chars, `stone.grantId` is a non-empty string, `stone.issuedAt` is valid RFC 3339.
2. `stone.ownerId` equals `"fx-" + chunk4(SHA-256(rawBytes(stone.ownerPublicKey)).hex[0..16])`.
3. `stone.allowedAgents` is a non-empty array of non-empty strings.
4. `Ed25519Verify(stone.ownerPublicKey, UTF8(JCS(stone without sig)), stone.sig) === true`.
5. **Kill-Switch Check:** `stone.status` MUST be `"ACTIVE"` or `"SCOPED"`. Any stone with `"PAUSED"`, `"REVOKED"`, or any other status MUST fail closed.
6. `task.spec === "sva-gov-task/1"`, `task.taskId` and `task.operatorAuthorizationRef` are non-empty strings, `task.witnessReceiptSha256` is 64 hex chars, `task.issuedAt` is valid RFC 3339.
7. `task.grantId === stone.grantId` and `stone.allowedAgents.includes(task.agent)`.

## 4. Honest Limits

- `SVA-GOV/1` proves that an operator's key signed the policy stone and that a conforming daemon checks it before claiming work.
- It cannot stop a compromised host that ignores verification checks entirely; combine it with branch protection, minimal repo scopes, and offline receipt verification (`SVA-ER/1`).
