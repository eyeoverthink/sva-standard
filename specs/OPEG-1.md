# OPEG/1 — Operational Protocol for Empirical Grounding (v1.0)

- **Wire Spec Identifier:** `"opeg/1"`
- **Media Type:** `application/opeg+json`
- **Status:** Reference Draft (Sovereign Verified Agency Open Standards Suite)
- **Cryptographic Primitives:** `SVA-ER/1` (`Ed25519` + `SHA-256` + `JCS` + RFC 6962 Merkle)

## 1. Purpose

Large language models default to fluent **direct inference** — producing plausible numerical, algebraic, or operational answers from weights alone without executing verification code. **`OPEG/1`** defines a fail-closed, 5-state pre-answer execution gate that blocks an agent from committing a claim or updating persistent memory unless:
1. Execution occurred (`mode === "EXECUTE_AND_RECEIVE"`, never `"DIRECT_INFERENCE"`).
2. Raw tool/runtime output (`R_raw`) passed through a deterministic sanitizer $\Sigma(R_{\text{raw}}) \to R_{\text{san}}$ producing structured JSON data.
3. The sanitized payload $R_{\text{san}}$ is cryptographically bound by `SHA-256(JCS(rSan))` to a valid, Ed25519-signed **`SVA-ER/1`** execution receipt (`boundReceipt`).

This enforces the strict source-priority hierarchy:

```text
Input_Source_Priority: [Runtime Receipt (SVA-ER/1)] > [Memory Artifact] > [Initial Prompt]
```

## 2. Five-State Execution Gate (`S0`–`S4`)

| State | Action | Gate / Fail-Closed Condition |
|---|---|---|
| **`S0` Goal** | Parse user goal & identify empirical claims requiring computation or measurement. | Identify required verification parameters. |
| **`S1` Hypothesis** | Emit structured execution plan (`CommandObject`) — **no final answer permitted**. | `DIRECT_INFERENCE` is forbidden for empirical claims. |
| **`S2` Execute & HALT** | Execute deterministic runtime / WASM / script and **HALT** generation until receipt arrives. | On runtime failure: halt and report dependency/execution error. |
| **`S3` Sanitize ($\Sigma$)** | Extract structured `R_san` from messy `R_raw`; mint & sign `SVA-ER/1` receipt binding `deliverableSha256 = SHA-256(JCS(rSan))`. | Malformed `R_raw` or unverified receipt blocks transition to `S4`. |
| **`S4` Commit** | Emit final answer & update memory substrate **only** from verified `R_san`. | Verifier independently checks `OPEG/1` commit envelope + `SVA-ER/1` receipt. |

## 3. Wire Format (`opeg/1`)

```json
{
  "spec": "opeg/1",
  "state": "S4_COMMIT",
  "mode": "EXECUTE_AND_RECEIVE",
  "sourcePriority": ["runtime_receipt", "memory_artifact", "initial_prompt"],
  "sanitizer": {
    "status": "SUCCESS",
    "rSan": { "exponent": 0.3333333333333333, "alpha": -1, "verified": true },
    "rSanSha256": "<64-hex SHA-256(JCS(rSan))>"
  },
  "receipt": { "...valid SVA-ER/1 receipt whose statement.deliverableSha256 === sanitizer.rSanSha256..." }
}
```

## 4. Mandatory Verification Rules (MUST FAIL CLOSED)

A conforming verifier MUST reject unless ALL checks succeed:
1. `spec === "opeg/1"` and `state === "S4_COMMIT"`.
2. `mode === "EXECUTE_AND_RECEIVE"` (any `"DIRECT_INFERENCE"` or unknown mode MUST be rejected).
3. `sourcePriority` is an array beginning with `"runtime_receipt"`.
4. `sanitizer` is an object with `status === "SUCCESS"`, non-null object `rSan`, and `rSanSha256 === SHA-256(UTF8(JCS(rSan)))`.
5. `receipt` is verified according to `receiptFormat` (default `"sva-er/1"`):
   - **`"sva-er/1"` (default):** `evaluateSvaEr1({ receipt, deliverable: JCS(rSan) })` returns `ok === true`, `outcome === "verified"`, and `deliverable === "verified"`.
   - **`"aer-1"` (format-agnostic interop profile for IETF `draft-zambo-aer1`):** `receipt` passes `AER-1` v0.4 core + Section 3.1 `metadata_hash` + `issuer_claims` binding verification, AND the decoded `canonical_bytes` payload binds `sanitizer.rSanSha256` (e.g. via `outputs` digest equality), with `clockAttestation: "absent"` and `issuerKeyBinding: "absent"` preserved explicitly rather than collapsed.

## 5. Honest Limits

- `OPEG/1` guarantees that an answer committed at `S4` was backed by an actual executed computation signed by the agency key and unmodified after execution.
- It does not prove that the mathematical model encoded inside the executed script itself is scientifically complete; it proves that the model actually ran that script and did not hallucinate or hand-edit the output.
