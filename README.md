# Sovereign Verified Agency (SVA) Open Standards v1.4

[![CI: Tri-Runtime Conformance](https://github.com/eyeoverthink/sva-standard/actions/workflows/ci.yml/badge.svg)](https://github.com/eyeoverthink/sva-standard/actions/workflows/ci.yml)
[![Live Zero-Backend Playgrounds](https://github.com/eyeoverthink/sva-standard/actions/workflows/pages.yml/badge.svg)](https://eyeoverthink.github.io/sva-standard/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Zero-dependency open wire standards (**`SVA-ER/1`**, **`VSC/1`**, **`EMA/1`**, **`OPEG/1`**, **`POR/1`**), a **90-vector golden conformance suite**, a **5-case bidirectional `AER-1` ↔ `SVA-ER/1` interop harness** (pinned to IETF `draft-zambo-aer1-26`, kit `1.6.1`), **3 independent reference runtimes** (**Node.js V8**, **W3C Browser WebCrypto**, and **Single-File Pure Java 25 with a built-in fuel-metered `i32`/`f64`/linear-memory WebAssembly VM**), a **5-scenario 4-agency local HTTP Immune & Quorum Mesh demo**, **3 published zero-dep npm packages**, and **4 live zero-backend browser playgrounds** for verifiable, local-first AI agents.

> **10-Second Verification (0 GPU, 0 API keys, 0 `npm install`):**
> - **Live Static Playgrounds ($0 GitHub Pages, 0 external CDNs):** https://eyeoverthink.github.io/sva-standard/
> - **CLI Conformance, Joint AER-1 Interop & Live 4-Agency Mesh Demo:**
>   ```bash
>   node conformance/v1/runners/node-verify.mjs           # 90/90 PASSED (~29 ms, node:crypto + V8 WebAssembly)
>   node conformance/v1/runners/webcrypto-verify.mjs      # 90/90 PASSED (~51 ms, W3C WebCrypto + WebAssembly, 0 node:crypto)
>   java conformance/v1/runners/SvaConformance.java       # 90/90 PASSED (~270 ms, 1-file pure Java 25 + pure-Java WASM VM)
>   node conformance/interop/aer1-svaer1/verify-interop.mjs  # 5/5 PASSED (draft-zambo-aer1-26 kit 1.6.1 <-> SVA-ER/1)
>   node demos/immune-mesh/run-demo.mjs                   # 4 local HTTP agencies, 5 scenarios, 0 GPU (~56 ms)
>   npm test                                              # Runs all 3 runtimes + interop + mesh demo + packages + playgrounds
>   ```

---

## 1. Live Zero-Backend Browser Playgrounds (`playgrounds/`)

Static HTML + ES modules (**0 backend servers, 0 external CDN requests, 0 build step** — works offline or directly on GitHub Pages):

| Lab | Live URL | Try in <10 Seconds |
|---|---|---|
| **Playground Hub** | https://eyeoverthink.github.io/sva-standard/ | Overview and offline verification guide |
| **1. AI Receipt Tamper Lab** | https://eyeoverthink.github.io/sva-standard/receipt-lab.html | Mint a live Ed25519 `SVA-ER/1` receipt in-browser and run **6 one-click "Try to Cheat" attacks** (trailing space, score inflation, stripped `IN_CLOUD`, duplicated `seq`, forged Merkle sibling, key swap) |
| **2. Privacy Membrane Lab** | https://eyeoverthink.github.io/sva-standard/membrane-lab.html | Clinic / DevOps / Hostile zero-width injection presets, lenient mangled-placeholder restore, and 1-click **digit-squeezed SSN egress leak** block |
| **3. Zero-Call Skill Binder Lab** | https://eyeoverthink.github.io/sva-standard/skill-lab.html | Zero-LLM binder induction (3/3 leave-one-out) + `<1 ms` fresh routing + **sales-tax, tip, and extra-quantity near-miss traps** |
| **4. OPEG/1 Grounding Gate Lab** | https://eyeoverthink.github.io/sva-standard/opeg-lab.html | Live `S0–S4` execution gate: block `DIRECT_INFERENCE` fail-closed, run a real numerical EP3 cubic perturbation check sanitized into `R_san` and signed as an `SVA-ER/1` receipt, then tamper `R_san` to watch verification catch it before commit |

---

## 2. The Five Open Wire Specifications (`specs/`)

Every wire format uses **only standard RFC primitives** (RFC 8032 `Ed25519`, FIPS 180-4 `SHA-256`, RFC 2104 `HMAC-SHA256`, RFC 8785 `JCS`, RFC 6962 `0x00`/`0x01` Merkle trees, RFC 3339 timestamps, WebAssembly Core 1.0) with zero proprietary wrappers.

| Spec | File | What It Proves at an Untrusted Boundary |
|---|---|---|
| **`SVA-ER/1`** | [specs/SVA-ER-1.md](specs/SVA-ER-1.md) | **Sovereign Verified Agency Execution Receipt (`application/sva-er+json`):** Offline verification of Ed25519-signed bundled execution entries, RFC 6962 `0x00`/`0x01` odd-node-promotion Merkle inclusion (immune to CVE-2012-2459), `entries.length === statement.entries` completeness, unique `seq`, byte-for-byte deliverable SHA-256, strict RFC 3339 timestamps, and named verification outcomes (`verified \| not_checked \| verification_failed`). Distinct from IETF `draft-zambo-aer1` (`AER-1`). |
| **`OPEG/1`** | [specs/OPEG-1.md](specs/OPEG-1.md) | **Operational Protocol for Empirical Grounding (`application/opeg+json`):** Pre-answer `S0–S4` execution gate forbidding `DIRECT_INFERENCE`, enforcing `Input_Source_Priority: [Runtime Receipt] > [Memory Artifact] > [Initial Prompt]`, and binding sanitized `R_san` outputs directly to signed `SVA-ER/1` receipts. |
| **`VSC/1` + `vsc-revoke/1` + `vsc-vote/1` + `vsc-veto/1`** | [specs/VSC-1.md](specs/VSC-1.md) | **Verifiable Skill Capsule, Zero-Rumor Revocation & Signed WASM Quorum:** Capability-free pure skill bundles (`wasm-core-1` / `js-pure-es2022`), zero-rumor counterexample tombstones, **signed WASM test-result quorum voting** (*"a vote is a signed test result, not an opinion"*), and human owner veto. |
| **`EMA/1`** | [specs/EMA-1.md](specs/EMA-1.md) | **Egress Membrane Attestation (`application/ema+json`):** Proves what crossed the network boundary — or proves `ONLY_ON_DEVICE` airgap (`egressBytes: 0`, `networkInterfaces: 0`) — with keyed `HMAC-SHA256` correlation tags and digit-squeezed PII leak auditing. |
| **`POR/1`** | [specs/POR-1.md](specs/POR-1.md) | **Proof-of-Reality Local-Hash Vault (`application/por+json`):** Privacy-preserving multi-modal witness vault built on `SVA-ER/1`'s exact RFC 6962 `0x00`/`0x01` odd-carry Merkle + Ed25519 primitives, ensuring raw biometrics never leave the device (`fx-xxxx-...` key-derived identity). |

---

## 3. Tri-Runtime Conformance Suite (`conformance/v1/`) & Joint `AER-1` Interop (`conformance/interop/`)

### 90 Golden Vectors Across 8 Suites (`conformance/v1/vectors.json`)
- `jcs` (**10** vectors, RFC 8785 number & UTF-16 sorting edge cases)
- `merkle` (**10** vectors, RFC 6962 odd-node promotion & CVE-2012-2459 defense)
- `svaer1` (**17** vectors, named outcomes `deliverable=not_checked`, `clock=attested|drift|unattested`, strict RFC 3339 timezone & leap-year regressions)
- `vsc1` (**17** vectors, JS/WASM capsules, `vsc-revoke/1` tombstones, `vsc-vote/1` self-vote & dishonest-digest rejections, `vsc-veto/1` owner veto)
- `ema1` (**14** vectors, sealed/airgapped crossings, digit-squeezed SSN leaks, `2^32` truncation, negative-count cancellation)
- `wasm_exec` (**14** vectors, real compiled WebAssembly Core 1.0 binaries — `i32`, IEEE-754 `f64`, linear memory + active data segments, fuel-metered infinite-loop DoS defense, live counterexample reproduction)
- `por1` (**4** vectors, 7-leaf local-hash vault + inclusion proof, 1-byte tamper detection, raw unhashed payload refusal)
- `opeg1` (**4** vectors, valid `EXECUTE_AND_RECEIVE` commit bound to `SVA-ER/1`, `DIRECT_INFERENCE` refusal, post-signing `R_san` tamper detection)

### Joint `AER-1` (`draft-zambo-aer1-26`, kit `1.6.1`) ↔ `SVA-ER/1` Interop Harness (`conformance/interop/aer1-svaer1/`)
Bidirectional clock-attestation and key-binding test vectors pinned against Brennan Zambo's `kit 1.6.1` evaluated corpus (`sha256:4ea44dc07125a6f9b7fa472450a30fb56265771cfe87b1772a02b03d1fc166f2`):
- `interop-01` (`svaer-04` `clock=unattested` ↔ `AER-1` v0.4 reading `clockAttestation=absent`, `issuerKeyBinding=absent`)
- `interop-02` (`svaer-05` `clock=drift`, `KEY_B` ↔ `AER-1` v0.4)
- `interop-03` (key-binding negative control: `KEY_B → KEY_A` swap in `SVA-ER/1` + `created_at` `metadata_hash` tamper in `AER-1` v0.4)
- `interop-04` (`AER-1` corpus `valid/bound-04.json` expressed in `SVA-ER/1` with `clock=attested` + `KEY_A`)
- `interop-05` (real hardware case: `FMP/1` offline Raspberry Pi mesh relay without RTC exporting `clock=unattested`)

Every `AER-1` v0.4 counterpart record in `vectors.json` was verified directly against `zambo.dev/aer1/corpus/v1.6.0/base/conformance.cjs`.

### Measured Results (`docs/evidence-sva-v1.4.json`)

| Runtime | External Dependencies | Result | Time |
|---|---:|---:|---:|
| Node.js `v24.11.1` (`node:crypto` + V8 `WebAssembly`) | 0 | **90 / 90** | ~29 ms |
| W3C Browser WebCrypto (`crypto.subtle` + `WebAssembly`) | 0 | **90 / 90** | ~51 ms |
| Java `25.0.1 LTS` (`SvaConformance.java`, single file + pure-Java `i32`/`f64`/memory WASM VM) | 0 | **90 / 90** | ~270 ms |
| Joint `AER-1` ↔ `SVA-ER/1` Interop (`verify-interop.mjs`) | 0 | **5 / 5** | ~5 ms |

---

## 4. Stage 5 Cross-Agency Immune & Quorum Mesh Demo (`demos/immune-mesh/`)

Run **4 real local HTTP agencies (`A, B, C, D` on `127.0.0.1`)** exchanging signed `vsc/1` WASM capsules, `vsc-revoke/1` tombstones, `vsc-vote/1` test-result votes, and `vsc-veto/1` owner vetoes in **~56 ms at 0 GPU calls**:

```bash
npm run demo:immune
```

Verifies live over HTTP:
1. **1-hop crash containment (`A → B → C`):** Local WASM divide-by-zero reproduction, quarantine, and TTL-clamped relay.
2. **Wrong-output containment & re-import block:** Local reproduction of `9980 != 8000` and hash-level re-import refusal.
3. **Byzantine auto-demotion (`D → B, C`):** 2 false flags auto-demote peer D (`trusted → known`), 3rd rejected HTTP `403`.
4. **Outbound Privacy Membrane & fail-closed admission:** Raw PII (`SSN`) blocked before socket egress; unsigned capsules rejected.
5. **Signed WASM Test-Result Quorum (`vsc-vote/1`) & Owner Veto (`vsc-veto/1`):** Self-vote from author A rejected, dishonest `resultsSha256` from peer D rejected as inconsistent, 2 consistent votes from B & C adopt `wasm_cube`, and signed owner `vsc-veto/1` withdraws it immediately.

---

## 5. Published Zero-Dependency npm Packages & Companion Repos

| Artifact | Link | Quick Verification (< 5s, 0 GPU) |
|---|---|---|
| [`@eyeoverthink/ai-receipt`](packages/ai-receipt/README.md) (`v1.3.0`) | [npmjs](https://www.npmjs.com/package/@eyeoverthink/ai-receipt) | `npx @eyeoverthink/ai-receipt verify <receipt.json> [deliverable.txt]` |
| [`@eyeoverthink/privacy-membrane`](packages/privacy-membrane/README.md) (`v1.2.0`) | [npmjs](https://www.npmjs.com/package/@eyeoverthink/privacy-membrane) | `npx @eyeoverthink/privacy-membrane seal "SSN 123-45-6789 elena@acme.org"` |
| [`@eyeoverthink/skill-crystallizer`](packages/skill-crystallizer/README.md) (`v1.2.0`) | [npmjs](https://www.npmjs.com/package/@eyeoverthink/skill-crystallizer) | `npx @eyeoverthink/skill-crystallizer` |
| **`eyeoverthink/singlefile-gpt`** (`v1.0.0`) | [GitHub](https://github.com/eyeoverthink/singlefile-gpt) | `java SingleFileGPT.java selftest` (79/79 pass, 0 deps) |
| **`eyeoverthink/fmp1-mesh`** (`v1.0.0`) | [GitHub](https://github.com/eyeoverthink/fmp1-mesh) | `fmp1 sim` + `fmp1 export-sva` (off-grid UDP/LoRa mesh exporting `SVA-ER/1` receipts) |

---

## Honest Limits

- **Scope of Verification:** Proven on deterministic numeric, code, and WebAssembly verification; verifying open-ended prose quality remains out of scope.
- **Host Trust Boundary:** `SVA-ER/1`, `OPEG/1`, `POR/1`, and `EMA/1` prove cryptographic integrity and completeness of what the signing host recorded; they cannot prevent a compromised host from lying *before* signing.
- **WASM Core 1.0 Profile (`SvaConformance.java`):** Implements capability-free `i32`, IEEE-754 `f64`, structured control flow, linear memory (`i32`/`f64` load/store, `memory.size`, `memory.grow`), and active data segments; `i64`, `f32`, indirect function tables, and SIMD are outside v1.4 scope.
- **Browser WebCrypto:** Ed25519 in `crypto.subtle` requires Chromium 113+, Firefox 129+, or Safari 17+ served over `https://` or `http://localhost`.
- **Reference Runtime:** Extracted from [eyeoverthink/eyeoverthink-agency](https://github.com/eyeoverthink/eyeoverthink-agency) (whose `master` branch remains untouched on its `contest-freeze` build).

## License

Apache-2.0 — see [LICENSE](LICENSE).
