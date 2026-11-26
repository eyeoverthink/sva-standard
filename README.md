# Sovereign Verified Agency (SVA) Open Standards v1.2

[![CI: Tri-Runtime Conformance](https://github.com/eyeoverthink/sva-standard/actions/workflows/ci.yml/badge.svg)](https://github.com/eyeoverthink/sva-standard/actions/workflows/ci.yml)
[![Live Zero-Backend Playgrounds](https://github.com/eyeoverthink/sva-standard/actions/workflows/pages.yml/badge.svg)](https://eyeoverthink.github.io/sva-standard/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Zero-dependency wire standards, a **76-vector golden conformance suite**, **3 independent reference runtimes** (**Node.js V8**, **W3C Browser WebCrypto**, and **Single-File Pure Java 25 with a built-in fuel-metered `i32`/`f64`/linear-memory WebAssembly VM**), a **4-agency local HTTP Immune System demo**, **3 publish-ready zero-dep packages**, and **3 live zero-backend browser playgrounds** for verifiable, local-first AI agents.

> **10-Second Verification (0 GPU, 0 API keys, 0 `npm install`):**
> - **Live Static Playgrounds ($0 GitHub Pages, 0 external CDNs):** https://eyeoverthink.github.io/sva-standard/
> - **CLI Conformance & Live 4-Agency Immune Mesh Demo:**
>   ```bash
>   node conformance/v1/runners/node-verify.mjs       # 76/76 PASSED (~24 ms, node:crypto + V8 WebAssembly)
>   node conformance/v1/runners/webcrypto-verify.mjs  # 76/76 PASSED (~38 ms, W3C WebCrypto + WebAssembly, 0 node:crypto)
>   java conformance/v1/runners/SvaConformance.java   # 76/76 PASSED (~268 ms, 1-file pure Java 25 + pure-Java WASM VM)
>   node demos/immune-mesh/run-demo.mjs               # 4 local HTTP agencies, 0 GPU (~60 ms)
>   npm test                                          # Runs all 3 runtimes + immune demo + packages + playgrounds
>   ```

---

## 1. Live Zero-Backend Browser Playgrounds (`playgrounds/`)

Static HTML + ES modules (**0 backend servers, 0 external CDN requests, 0 build step** — works offline or directly on GitHub Pages):

| Lab | Live URL | Try in <10 Seconds |
|---|---|---|
| **Playground Hub** | https://eyeoverthink.github.io/sva-standard/ | Overview and offline verification guide |
| **AI Receipt Tamper Lab** | https://eyeoverthink.github.io/sva-standard/receipt-lab.html | Mint a live Ed25519 v2 receipt in-browser and run **6 one-click "Try to Cheat" attacks** (trailing space, score inflation, stripped `IN_CLOUD`, duplicated `seq`, forged Merkle sibling, key swap) |
| **Privacy Membrane Lab** | https://eyeoverthink.github.io/sva-standard/membrane-lab.html | Clinic / DevOps / Hostile zero-width injection presets, lenient mangled-placeholder restore, and 1-click **digit-squeezed SSN egress leak** block |
| **Zero-Call Skill Binder Lab** | https://eyeoverthink.github.io/sva-standard/skill-lab.html | Zero-LLM binder induction (3/3 leave-one-out) + `<1 ms` fresh routing + **sales-tax, tip, and extra-quantity near-miss traps** |

---

## 2. The Three Open Wire Specifications (`specs/`)

Every wire format uses **only standard RFC primitives** (RFC 8032 `Ed25519`, FIPS 180-4 `SHA-256`, RFC 2104 `HMAC-SHA256`, RFC 8785 `JCS`, RFC 6962 `0x00`/`0x01` Merkle trees, WebAssembly Core 1.0) with zero proprietary wrappers.

| Spec | File | What It Proves at an Untrusted Boundary |
|---|---|---|
| **`AER/1`** | [specs/AER-1.md](specs/AER-1.md) | **Agent Execution Receipt (`application/aer+json`):** Offline verification of signed execution entries, RFC 6962 `0x00`/`0x01` Merkle inclusion (odd-node promotion — immune to CVE-2012-2459), `entries.length === statement.entries` completeness (cannot strip `IN_CLOUD` or blocked-egress entries), unique `seq`, byte-for-byte deliverable SHA-256, and honest clock status (`attested \| drift \| unattested`). |
| **`VSC/1` + `vsc-revoke/1`** | [specs/VSC-1.md](specs/VSC-1.md) | **Verifiable Skill Capsule & Zero-Rumor Revocation:** Portable, capability-free pure skill bundles (`wasm-core-1` or `js-pure-es2022`) with fail-closed Ed25519 signatures and `vsc-revoke/1` tombstones carrying signed counterexamples. Receivers ignore rumors and quarantine **only** after locally executing the counterexample and reproducing the fault. |
| **`EMA/1`** | [specs/EMA-1.md](specs/EMA-1.md) | **Egress Membrane Attestation (`application/ema+json`):** Proves what crossed the network boundary — or proves `ONLY_ON_DEVICE` airgap (`egressBytes: 0`, `networkInterfaces: 0`) — with keyed `HMAC-SHA256` correlation tags and digit-squeezed PII leak auditing. |

---

## 3. Tri-Runtime Conformance Suite (`conformance/v1/`)

**76 deterministic golden vectors** generated from fixed RFC 8032 Ed25519 seeds across 6 suites:
- `jcs` (**10** vectors, including `-0`, `0.0001`, `1e-7`, `1e20`, `1e21` ECMAScript/RFC 8785 edge cases)
- `merkle` (**10** vectors, including CVE-2012-2459 odd-leaf duplication forgery & `0x00`/`0x01` second-preimage defense)
- `aer1` (**15** vectors, valid + stripped entries, duplicated `seq`, forged proofs, swapped keys, empty `clock.issuedAt`)
- `vsc1` (**13** vectors, valid JS/WASM capsules + `vsc-revoke/1` tombstones + missing signatures, bad base64, capability violations)
- `ema1` (**14** vectors, valid sealed/airgapped crossings + digit-squeezed SSN leaks, `2^32` integer truncation, negative-count cancellation, per-type tag mismatch)
- `wasm_exec` (**14** vectors): **real compiled WebAssembly Core 1.0 binaries** covering `i32` compute (`discount_cents`, `tax_and_split`, `sum_to_n` loop/branching, divide-by-zero trap), **IEEE-754 `f64`** (`compound_discount`, `harmonic_mean`, `NaN → i32.trunc_f64_s` invalid conversion trap), **linear memory** (active data segment + `i32.load`/`i32.store` sum, `f64.store`/`f64.load` + `memory.grow`/`memory.size`, out-of-bounds `mem_oob` trap), adversarial infinite-loop DoS stopped by deterministic fuel metering, end-to-end `vsc-revoke/1` counterexample fault reproduction, and corrupt-section structural rejection — executed bit-for-bit identically in **Node V8**, **W3C Browser WebAssembly**, and **Single-File Pure Java 25**.

### Measured Results (`docs/evidence-sva-v1.2.json`)

| Runtime | External Dependencies | Result | Time |
|---|---:|---:|---:|
| Node.js `v24.11.1` (`node:crypto` + V8 `WebAssembly`) | 0 | **76 / 76** | 24.2 ms |
| W3C Browser WebCrypto (`crypto.subtle` + `WebAssembly`) | 0 | **76 / 76** | 38.4 ms |
| Java `25.0.1 LTS` (`SvaConformance.java`, single file + pure-Java `i32`/`f64`/memory WASM VM) | 0 | **76 / 76** | 268.5 ms |

---

## 4. Stage 5 Cross-Agency Immune System Demo (`demos/immune-mesh/`)

Run **4 real local HTTP agencies (`A, B, C, D` on `127.0.0.1`)** exchanging signed `vsc/1` WASM capsules and `vsc-revoke/1` tombstones in **~60 ms at 0 GPU calls**:

```bash
npm run demo:immune
```

Verifies live over HTTP:
1. **1-hop crash containment (`A → B → C`):** B reproduces a WASM divide-by-zero trap locally, quarantines the skill, increments `repConfirmed[A]`, and relays (TTL-clamped) to C.
2. **Wrong-output containment & re-import block:** B & C reproduce `9980 != 8000` locally, quarantine the `codeSha256`, and reject re-import attempts of that hash.
3. **Byzantine auto-demotion (`D → B, C`):** Malicious peer D sends 2 irreproducible false flags against a healthy skill; B & C keep it `active` (`falseQuarantines: 0`), auto-demote D (`trusted → known`), and reject D's 3rd request with HTTP `403`.
4. **Outbound Privacy Membrane & fail-closed admission:** Raw PII (`SSN`) inside an advisory note is blocked before leaving the socket; unsigned capsules (`sig: null`) are rejected.

---

## 5. Published Zero-Dependency npm Packages (`packages/`)

Every package is live on **npmjs.org** at `v1.2.0` with strict `files`/`exports`, Apache-2.0 `LICENSE`, dedicated `README.md`, and **0 runtime dependencies** (~9–10.5 kB packed):

| Package | npm | Quick `npx` Verification (< 5s, 0 GPU, 0 clone) |
|---|---|---|
| [`@eyeoverthink/ai-receipt`](packages/ai-receipt/README.md) | [npmjs](https://www.npmjs.com/package/@eyeoverthink/ai-receipt) | `npx @eyeoverthink/ai-receipt verify <receipt.json> [deliverable.txt]` |
| [`@eyeoverthink/privacy-membrane`](packages/privacy-membrane/README.md) | [npmjs](https://www.npmjs.com/package/@eyeoverthink/privacy-membrane) | `npx @eyeoverthink/privacy-membrane seal "SSN 123-45-6789 elena@acme.org"` |
| [`@eyeoverthink/skill-crystallizer`](packages/skill-crystallizer/README.md) | [npmjs](https://www.npmjs.com/package/@eyeoverthink/skill-crystallizer) | `npx @eyeoverthink/skill-crystallizer` |

---

## 6. Release Playbook & Launch Kits (`docs/`)

- [docs/RELEASE-PLAYBOOK.md](docs/RELEASE-PLAYBOOK.md) — 12-week / 6-stage release schedule & 72-hour launch cadence.
- [docs/launch/STAGE-1-SINGLEFILE-GPT.md](docs/launch/STAGE-1-SINGLEFILE-GPT.md) — Stage 1 (`SingleFileGPT.java`) launch kit.
- [docs/launch/STAGE-2-SKILL-CRYSTALLIZER.md](docs/launch/STAGE-2-SKILL-CRYSTALLIZER.md) — Stage 2 (`@eyeoverthink/skill-crystallizer` + `skill-lab.html`) launch kit.
- [docs/launch/STAGE-6-SVA-STANDARD.md](docs/launch/STAGE-6-SVA-STANDARD.md) — Stage 6 (`SVA v1.2` + 51-bug audit post-mortem) launch kit.

---

## Honest Limits

- **Scope of Verification:** Currently proven on deterministic numeric, code, and WebAssembly verification; verifying open-ended prose quality remains the next frontier.
- **Host Trust Boundary:** `AER/1` and `EMA/1` prove cryptographic integrity and completeness of what the signing agency recorded; they cannot prevent a compromised host from lying *before* signing.
- **WASM Core 1.0 Profile (`SvaConformance.java`):** The single-file pure-Java fuel-metered WASM VM implements capability-free `i32`, IEEE-754 `f64`, structured control flow (`block`/`loop`/`br`/`br_if`), linear memory (`i32.load`/`i32.store`/`f64.load`/`f64.store`/`memory.size`/`memory.grow`), and active data segments; `i64`, `f32`, indirect function tables, and SIMD are outside v1.2 scope.
- **Browser WebCrypto:** Ed25519 in `crypto.subtle` requires Chromium 113+, Firefox 129+, or Safari 17+ served over `https://` or `http://localhost` (raw `file://` blocks ES module imports).
- **Reference Runtime:** Extracted from [eyeoverthink/eyeoverthink-agency](https://github.com/eyeoverthink/eyeoverthink-agency) (whose `master` branch remains untouched on its `contest-freeze` build).

## License

Apache-2.0 — see [LICENSE](LICENSE).
