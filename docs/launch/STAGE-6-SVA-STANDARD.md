# Stage 6 Launch Kit — SVA Open Standards v1.3 (`eyeoverthink/sva-standard`) & 51-Bug Audit Post-Mortem (Weeks 11–12)

> **Launch Guardrails Verified:** Zero bio/sci-fi lore · All 5 Critical AUDIT.md findings (C1–C5) + H4/H5/H6/H9/M1 closed & verified BEFORE inviting "try to break it" · Spec renamed `AER/1` → `SVA-ER/1` to avoid colliding with IETF `draft-zambo-aer1` (`AER-1`) · `<10s` 0-GPU 3-runtime CLI + 3 live static browser playgrounds · 100% Apache-2.0 local-first · Explicit honest limits.

---

## T-24h Pre-Flight Checklist
- [ ] Clean git tag `v1.3.0` + GitHub Release on `eyeoverthink/sva-standard`.
- [ ] Verify all 3 live playgrounds in incognito tab:
  - https://eyeoverthink.github.io/sva-standard/receipt-lab.html (6/6 tamper attacks caught)
  - https://eyeoverthink.github.io/sva-standard/membrane-lab.html (digit-squeezed SSN leak + zero-width injection caught)
  - https://eyeoverthink.github.io/sva-standard/skill-lab.html (valid tasks pass, 3/3 traps refused)
- [ ] Verify `<10s` 0-GPU verification suite on a clean clone:
  ```bash
  node conformance/v1/runners/node-verify.mjs       # 78/78 PASSED (~24 ms)
  node conformance/v1/runners/webcrypto-verify.mjs  # 78/78 PASSED (~38 ms)
  java conformance/v1/runners/SvaConformance.java   # 78/78 PASSED (~270 ms)
  node demos/immune-mesh/run-demo.mjs               # 4 local HTTP agencies, 0 GPU (~60 ms)
  ```

---

## T+0h — 90-Second Own-Voice YouTube Demo Script

- **0:00–0:15 (Hook):** "When an AI agent claims it kept your data local and verified its output, how do you check it without trusting the agent? We extracted three zero-dependency open wire standards — `SVA-ER/1`, `VSC/1`, and `EMA/1` — built strictly on standard RFCs: Ed25519, SHA-256, RFC 8785 JCS, RFC 6962 Merkle trees, RFC 3339 timestamps, and WebAssembly Core 1.0."
- **0:15–0:45 (3 Commands, 3 Runtimes, 78 Golden Vectors):** "Clone the repo — zero `npm install`, zero Maven, zero GPU. Run `node-verify.mjs`: 78/78 in 24 ms. Run `webcrypto-verify.mjs` with zero `node:crypto` imports: 78/78 in 38 ms. Run `SvaConformance.java` — one pure Java file with its own fuel-metered `i32`/`f64`/linear-memory WASM VM: 78/78 in 270 ms. Bit-for-bit identical across V8, Browser WebCrypto, and Java 25."
- **0:45–1:10 (Try to Cheat Live in Browser + 4-Agency Immune Demo):** "Don't even clone it — open the static GitHub Pages Tamper Lab. Mint a live Ed25519 receipt in your browser, then click all 6 'Try to Cheat' attacks: add 1 trailing space, inflate a critic score, strip an `IN_CLOUD` entry, duplicate a sequence number, forge a Merkle sibling, swap the agency key. Every attack is caught offline. Then run `npm run demo:immune`: 4 real local HTTP agencies reproduce a buggy WASM counterexample in 60 ms, quarantine the hash, and auto-demote a Byzantine peer after 2 false flags."
- **1:10–1:30 (Why We Fixed 5 Critical Bugs First + CTA):** "Before publishing this, we ran a brutal 51-finding internal audit — catching a Node `--permission` network escape, a missing-signature plasmid bypass, stripped receipt entries, sibling-prefix path traversal, and IPv4-mapped IPv6 SSRF — and closed every Critical finding with regression vectors. Now try to break the verifier."

---

## T+0h — Show HN Submission

**Title:** `Show HN: SVA v1.3 – Zero-dep AI receipt (SVA-ER/1), privacy membrane, and WASM skill specs`

**Immediate First Comment (Post within 60 seconds):**
> Hi HN — we extracted three small, zero-dependency wire standards for verifiable, local-first AI agents (`Apache-2.0`):
>
> 1. **`SVA-ER/1` (Sovereign Verified Agency Execution Receipt, `application/sva-er+json`):** Offline verification of Ed25519-signed bundled execution logs using RFC 8032, JCS (RFC 8785), RFC 3339 timestamps, and RFC 6962 `0x00`/`0x01` odd-node-promotion Merkle proofs (immune to CVE-2012-2459), returning explicit named outcomes (`deliverable: not_checked` when omitted, `clock: attested | drift | unattested`). *(Note: distinct from Brennan Zambo's IETF `draft-zambo-aer1` / `AER-1`; renamed from our working label after his review to keep the ecosystem unambiguous.)*
> 2. **`VSC/1` + `vsc-revoke/1` (Verifiable Skill Capsule & Zero-Rumor Revocation):** Portable capability-free `wasm-core-1` / `js-pure-es2022` skill bundles with fail-closed Ed25519 signatures and counterexample tombstones. Receivers ignore rumors and quarantine a skill hash **only** after locally executing the counterexample and reproducing the fault.
> 3. **`EMA/1` (Egress Membrane Attestation):** Signed proof of what crossed a network boundary — or proof of `ONLY_ON_DEVICE` airgap (`egressBytes: 0`, `networkInterfaces: 0`) — with keyed HMAC-SHA256 correlation tags and digit-squeezed PII leak auditing (`123456789` caught even without dashes).
>
> **Verify in <10 seconds (0 GPU, 0 API keys, 0 installs):**
> - Live static browser labs (0 backend, 0 external CDN requests): https://eyeoverthink.github.io/sva-standard/
> - Tri-runtime 78-vector golden conformance + 4-agency HTTP immune demo:
>   ```
>   node conformance/v1/runners/node-verify.mjs       # 78/78 (~24 ms, Node V8)
>   node conformance/v1/runners/webcrypto-verify.mjs  # 78/78 (~38 ms, W3C WebCrypto, 0 node:crypto)
>   java conformance/v1/runners/SvaConformance.java   # 78/78 (~270 ms, 1-file pure Java + i32/f64/memory WASM VM)
>   node demos/immune-mesh/run-demo.mjs               # 4 local HTTP agencies, 0 GPU (~60 ms)
>   ```
>
> **Audit Before Hype:** Before inviting anyone to break this, we ran a 51-finding security/bug audit on the reference agency and closed all 5 Critical findings (Node `--permission` network egress escape via exotic primordials, fail-open `sig: null` plasmid admission, stripped receipt entries, sibling-prefix static traversal, and IPv4-mapped IPv6 SSRF) — turning those exact bypasses into negative golden vectors here.
>
> **Honest Limits:**
> - Receipts prove cryptographic integrity and completeness of what the signing host recorded; they cannot prevent a rooted host from lying *before* signing.
> - Currently proven on deterministic numeric/code/WASM verification; verifying open-ended prose quality remains the next frontier.
> - The single-file pure-Java fuel-metered WASM VM covers `i32`, `f64`, structured control flow, linear memory, and active data segments; `i64`, `f32`, indirect function tables, and SIMD are intentionally out of v1.3 scope.
> - Browser WebCrypto Ed25519 requires Chromium 113+, Firefox 129+, or Safari 17+ over `https://` or `http://localhost`.

---

## T+4h — 5-Post X Receipts Thread

1. **Post 1 (Hook + Results Table):** Three open RFC-only wire standards for verifiable local-first AI agents (`SVA-ER/1`, `VSC/1`, `EMA/1`) — 78 golden vectors passing bit-for-bit identically across Node V8 (24 ms), W3C Browser WebCrypto (38 ms), and a single pure Java file with its own fuel-metered `i32`/`f64`/memory WASM VM (270 ms). Zero dependencies.
2. **Post 2 (Terminal Clip):** 4 commands, 0 `npm install`, 0 GPU: tri-runtime 78/78 conformance + a 4-agency local HTTP immune mesh that reproduces a faulty WASM counterexample, quarantines it across 1-hop gossip, and auto-demotes a Byzantine peer in 60 ms. *[Attach 15s terminal clip]*
3. **Post 3 (Zero-Backend Playgrounds):** Try to break it right in your browser — 0 backend, 0 external CDN calls:
   - Mint an Ed25519 receipt & run 6 tamper attacks: https://eyeoverthink.github.io/sva-standard/receipt-lab.html
   - Leak a digit-squeezed SSN & zero-width injection: https://eyeoverthink.github.io/sva-standard/membrane-lab.html
   - Try to trick the zero-LLM skill binder: https://eyeoverthink.github.io/sva-standard/skill-lab.html
4. **Post 4 (The Bugs & Critique We Fixed First):** Closed our own 5 Critical audit findings (CVE-2012-2459 odd-leaf Merkle collisions, stripped `IN_CLOUD` entries, `2^32` Java truncation) AND renamed `AER/1` → `SVA-ER/1` + added RFC 3339 leap-year/timezone checks & named verification outcomes within hours of feedback from IETF `draft-zambo-aer1` author Brennan Zambo.
5. **Post 5 (Open Challenge):** Open challenge: find a conformance discrepancy between `node-verify.mjs`, `webcrypto-verify.mjs`, and `SvaConformance.java` — or a bypass in any of the 3 published npm packages (`@eyeoverthink/ai-receipt`, `privacy-membrane`, `skill-crystallizer`). Valid PR/issue = new golden vector + patch in 48 hours.

---

## T+24h — Native Markdown Post (`r/LocalLLaMA` / `r/selfhosted` / `r/programming`)

**Title:** `We audited our local-first AI agent stack (51 bugs, 5 Critical), fixed the crypto/sandbox gaps, and extracted 3 zero-dependency open specs (SVA-ER/1, VSC/1, EMA/1) with Node, Browser WebCrypto, and pure-Java WASM conformance`

*(Structure: 1) The 5 Critical bugs we actually found in our own code with exact failing inputs, 2) The 3 RFC-only wire formats we extracted + why we renamed `SVA-ER/1` to avoid colliding with IETF `draft-zambo-aer1`, 3) Exact 78/78 tri-runtime table + 60 ms 4-agency HTTP immune demo + live `npx` commands, 4) Honest limits on numeric/code vs prose verification.)*

---

## T+72h — 60-Second YouTube Short Template
- Pick the sharpest edge case / conformance discrepancy / red-team finding raised by the HN or Reddit community, add it as golden vector #79 across all 3 runtimes (Node, WebCrypto, Java), ship patch `v1.3.1` within 48 hours, and show all 3 runtimes turning green.
