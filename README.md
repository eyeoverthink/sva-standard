# Sovereign Verified Agency (SVA) Open Standards v1.1

Zero-dependency wire standards, a **70-vector golden conformance suite**, **3 independent reference runtimes** (**Node.js**, **W3C Browser WebCrypto**, and **Single-File Pure Java 25 with a built-in fuel-metered WebAssembly VM**), **3 standalone packages**, and **3 offline browser playgrounds** for verifiable, local-first AI agents.

> **10-Second Verification (0 GPU, 0 API keys, 0 npm installs):**
> ```bash
> node conformance/v1/runners/node-verify.mjs       # 70/70 PASSED (node:crypto + V8 WebAssembly)
> node conformance/v1/runners/webcrypto-verify.mjs  # 70/70 PASSED (W3C WebCrypto + WebAssembly, 0 node:crypto)
> java conformance/v1/runners/SvaConformance.java   # 70/70 PASSED (1-file pure Java 25 + pure-Java WASM VM)
> npm test                                          # Runs all 3 runtimes + package CLIs + playground checks
> ```

---

## 1. The Three Open Wire Specifications (`specs/`)

Every wire format uses **only standard RFC primitives** (RFC 8032 `Ed25519`, FIPS 180-4 `SHA-256`, RFC 2104 `HMAC-SHA256`, RFC 8785 `JCS`, RFC 6962 `0x00`/`0x01` Merkle trees, WebAssembly Core 1.0) with zero proprietary wrappers.

| Spec | File | What It Proves at an Untrusted Boundary |
|---|---|---|
| **`AER/1`** | [specs/AER-1.md](specs/AER-1.md) | **Agent Execution Receipt (`application/aer+json`):** Offline verification of signed execution entries, RFC 6962 `0x00`/`0x01` Merkle inclusion (odd-node promotion — immune to CVE-2012-2459), `entries.length === statement.entries` completeness (cannot strip `IN_CLOUD` or blocked-egress entries), unique `seq`, byte-for-byte deliverable SHA-256, and honest clock status (`attested \| drift \| unattested`). |
| **`VSC/1` + `vsc-revoke/1`** | [specs/VSC-1.md](specs/VSC-1.md) | **Verifiable Skill Capsule & Zero-Rumor Revocation:** Portable, capability-free pure skill bundles (`wasm-core-1` or `js-pure-es2022`) with fail-closed Ed25519 signatures and `vsc-revoke/1` tombstones carrying signed counterexamples. Receivers ignore rumors and quarantine **only** after locally executing the counterexample and reproducing the fault. |
| **`EMA/1`** | [specs/EMA-1.md](specs/EMA-1.md) | **Egress Membrane Attestation (`application/ema+json`):** Proves what crossed the network boundary — or proves `ONLY_ON_DEVICE` airgap (`egressBytes: 0`, `networkInterfaces: 0`) — with keyed `HMAC-SHA256` correlation tags and digit-squeezed PII leak auditing. |

---

## 2. Tri-Runtime Conformance Suite (`conformance/v1/`)

**70 deterministic golden vectors** generated from fixed RFC 8032 Ed25519 seeds across 6 suites:
- `jcs` (**10** vectors, including `-0`, `0.0001`, `1e-7`, `1e20`, `1e21` ECMAScript/RFC 8785 edge cases)
- `merkle` (**10** vectors, including CVE-2012-2459 odd-leaf duplication forgery & `0x00`/`0x01` second-preimage defense)
- `aer1` (**15** vectors, valid + stripped entries, duplicated `seq`, forged proofs, swapped keys, empty `clock.issuedAt`)
- `vsc1` (**13** vectors, valid JS/WASM capsules + `vsc-revoke/1` tombstones + missing signatures, bad base64, capability violations)
- `ema1` (**14** vectors, valid sealed/airgapped crossings + digit-squeezed SSN leaks, `2^32` integer truncation, negative-count cancellation, per-type tag mismatch)
- `wasm_exec` (**8** vectors): **real compiled WebAssembly Core 1.0 binaries** (`discount_cents`, `tax_and_split`, `sum_to_n` loop/branching, divide-by-zero trap, adversarial infinite-loop DoS stopped by deterministic fuel metering, end-to-end `vsc-revoke/1` counterexample fault reproduction, and corrupt-section WASM rejection) executed bit-for-bit identically in **Node V8**, **W3C Browser WebAssembly**, and **Single-File Pure Java 25**.

### Measured Results (`docs/evidence-sva-v1.1.json`)

| Runtime | External Dependencies | Result | Time |
|---|---:|---:|---:|
| Node.js `v24.11.1` (`node:crypto` + V8 `WebAssembly`) | 0 | **70 / 70** | 25.4 ms |
| W3C Browser WebCrypto (`crypto.subtle` + `WebAssembly`) | 0 | **70 / 70** | 36.7 ms |
| Java `25.0.1 LTS` (`SvaConformance.java`, single file + pure-Java WASM VM) | 0 | **70 / 70** | 249.5 ms |

---

## 3. Unbundled Zero-Dependency Packages (`packages/`)

| Package | Purpose | Quick CLI Test |
|---|---|---|
| `@eyeoverthink/ai-receipt` | Offline Ed25519 + RFC 6962 receipt verification | `node packages/ai-receipt/bin/ai-receipt.js verify <receipt.json> [deliverable.txt]` |
| `@eyeoverthink/privacy-membrane` | Deterministic PII/secret sealing, digit-squeezed egress audit, Sentinel zero-width injection guard | `node packages/privacy-membrane/bin/privacy-membrane.js seal "SSN 123-45-6789 elena@acme.org"` |
| `@eyeoverthink/skill-crystallizer` | Zero-LLM binder induction with leave-one-out validation & positional wording gates | `node packages/skill-crystallizer/bin/skill-crystallizer.js` |

---

## 4. Zero-Backend Interactive Browser Playgrounds (`playgrounds/`)

Static HTML + ES modules (**0 backend servers, 0 external CDN requests, 0 build step** — works offline or hosted on GitHub Pages for \$0):
1. `playgrounds/receipt-lab.html` — Mint a live Ed25519 v2 receipt in-browser and run 6 one-click **"Try to Cheat"** attacks.
2. `playgrounds/membrane-lab.html` — Clinic / DevOps / Hostile zero-width presets, mangled placeholder restore, and 1-click **"Simulate Egress Leak"**.
3. `playgrounds/skill-lab.html` — Zero-call binder induction + sales-tax, tip, and extra-number near-miss traps.

---

## Honest Limits

- **WASM Core 1.0 Subset (`SvaConformance.java`):** The single-file pure-Java fuel-metered WASM VM currently implements the capability-free `i32` compute & structured control-flow subset (`block`/`loop`/`br`/`br_if`/`local.*`/`i32.*`); `f64` and linear-memory opcodes are planned for v1.2.
- **Browser WebCrypto:** Ed25519 in `crypto.subtle` requires Chromium 113+, Firefox 129+, or Safari 17+ served over `https://` or `http://localhost` (raw `file://` blocks ES module imports).
- **Reference Runtime:** Built as the open standard extracted from [eyeoverthink/eyeoverthink-agency](https://github.com/eyeoverthink/eyeoverthink-agency) (which remains untouched on its `contest-freeze` build).

## License

Apache-2.0 — see [LICENSE](LICENSE).
