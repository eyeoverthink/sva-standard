# VSC/1 — Verifiable Skill Capsule & Counterexample Revocation (`vsc-revoke/1`)

- **Media Types:** `application/vsc+json`, `application/vsc-revoke+json`
- **Status:** Reference Draft (Sovereign Verified Agency Open Standards Suite)
- **Cryptographic Primitives:** `Ed25519` (RFC 8032), `SHA-256`, `JCS` (RFC 8785)

## 1. Purpose

`VSC/1` defines a portable, capability-free, cryptographically signed skill artifact that can move between independent AI runtimes (Node.js, Browser WebAssembly, JVM) without leaking tasks or trusting the sender blindly.

`vsc-revoke/1` defines a **zero-rumor immune tombstone**: any peer can announce that a skill is faulty, **but a receiver MUST ignore rumors and quarantine the skill ONLY after executing `counterexample.input` locally and reproducing the fault**.

## 2. Skill Capsule Format (`vsc/1`)

No custom DNA/ACGT wrappers appear on the wire. Only plain JCS-canonicalizable JSON:

```json
{
  "spec": "vsc/1",
  "name": "sequential_discount",
  "version": "1.0.0",
  "runtime": "wasm-core-1 | js-pure-es2022",
  "encoding": "utf8 | base64",
  "code": "function main({ price, d1, d2 }) { return Math.round(price * (1 - d1) * (1 - d2) * 100) / 100; }",
  "codeSha256": "<64-hex SHA-256 over raw decoded code bytes>",
  "params": { "type": "object", "required": ["price", "d1", "d2"] },
  "tests": [
    { "input": { "price": 100, "d1": 0.2, "d2": 0.1 }, "output": 72 }
  ],
  "capabilities": [],
  "signer": "<64-hex Ed25519 raw pubkey>",
  "sig": "<128-hex Ed25519 signature over UTF8(JCS(capsule without sig))>"
}
```

### Mandatory Admission Checks (Fail Closed)
1. `spec === "vsc/1"`, `runtime` is strictly `"wasm-core-1"` or `"js-pure-es2022"`, and `capabilities` is an empty array `[]` (pure functions only).
2. `name` matches `/^[a-z][a-z0-9_-]{1,63}$/` (blocks prototype-pollution names and path traversal).
3. Enforce strict encoding pairing: `runtime === "js-pure-es2022"` MUST use `encoding === "utf8"`; `runtime === "wasm-core-1"` MUST use `encoding === "base64"` (strict RFC 4648 base64, rejecting invalid characters). Decode `code`; `SHA256(codeBytes) === codeSha256`.
4. If `runtime === "wasm-core-1"`, wire verification MUST check the 8-byte WebAssembly v1 magic + version header (`00 61 73 6d 01 00 00 00`); runtime admission MUST additionally execute full `WebAssembly.validate(codeBytes)` before invoking. Conforming SVA v1.2 runtimes execute capability-free WebAssembly Core 1.0 (`i32`, IEEE-754 `f64`, structured control flow, linear memory with active data segments & bounded `memory.grow`, and deterministic fuel metering) bit-for-bit identically across Node.js V8, W3C Browser WebAssembly, and Single-File Pure Java.
5. `tests` MUST be a non-empty array.
6. `signer` is 64 hex chars, `sig` is 128 hex chars (NEVER optional), and `Ed25519Verify(signer, UTF8(JCS(capsule without sig)), sig) === true`.
7. Receivers MUST keep imported capsules on probation until locally re-verified on live tasks.

## 3. Zero-Rumor Revocation Tombstone (`vsc-revoke/1`)

```json
{
  "spec": "vsc-revoke/1",
  "targetCodeSha256": "<64-hex>",
  "kind": "crash | wrong_output | nondeterministic | invariant_violation",
  "counterexample": {
    "input": { "price": 100, "d1": 0.2, "d2": 0.1 },
    "expected": 72,
    "observed": 70
  },
  "issuedAt": "2026-11-26T00:00:00.000Z",
  "signer": "<64-hex Ed25519 raw pubkey>",
  "sig": "<128-hex Ed25519 signature over UTF8(JCS(tombstone without sig))>"
}
```

### Mandatory Tombstone Checks
1. `spec === "vsc-revoke/1"`, `targetCodeSha256` is 64 hex chars, `kind` is one of the four allowed values.
2. `counterexample` is an object containing a non-undefined `input`.
3. `signer` is 64 hex chars, `sig` is 128 hex chars, and `Ed25519Verify(signer, UTF8(JCS(tombstone without sig)), sig) === true`.
4. **Local Reproduction Rule (Runtime):** A valid tombstone signature authorizes *testing* the counterexample locally — never blind quarantine. Receivers quarantine `targetCodeSha256` only when local execution confirms the fault, and demote peers that repeatedly submit irreproducible tombstones.
