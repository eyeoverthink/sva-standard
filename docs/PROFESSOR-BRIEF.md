# Sovereign Verified Agency (SVA) — Technical Overview for Faculty Review

**Author:** Vaughn Scott (`eyeoverthink`)  
**Standard Suite:** [`eyeoverthink/sva-standard`](https://github.com/eyeoverthink/sva-standard) (`v1.7.0`, Apache-2.0)  
**Epistemic Judge Reference:** [`eyeoverthink/logic-chain-judge`](https://github.com/eyeoverthink/logic-chain-judge) (`v1.0.0`, Apache-2.0)  
**Live Offline Browser Playgrounds (0 backend, 0 CDN):** [eyeoverthink.github.io/sva-standard](https://eyeoverthink.github.io/sva-standard/)

---

## 1. Core Thesis: Verifiable Trust Boundaries for AI Agents

Autonomous AI agents routinely mix deterministic computation, sensitive personal data, tool invocations, and open-ended natural-language reasoning. Most current agent frameworks rely on **testimony** (*"the agent said it ran the test and redacted the PII"*).

This project replaces agent testimony with a **three-layer, zero-dependency verification architecture** where every claim is either **cryptographically/mechanically verified** or **explicitly bounded with measured uncertainty**:

| Layer | Open Specifications & Artifacts | What It Verifies | Verification Mechanism |
| --- | --- | --- | --- |
| **1. Execution Proof** | `SVA-ER/1`, `VSC/1`, `POR/1`, [`fraymus-receipts`](https://github.com/eyeoverthink/fraymus-receipts) (`FRYM` WASM v1), [`fmp1-mesh`](https://github.com/eyeoverthink/fmp1-mesh) | *Did this exact tool/WASM skill run and produce this exact output?* | RFC 8785 JCS + RFC 8032 Ed25519 + RFC 6962 Merkle proofs + fuel-metered WASM VM + custom-section binary binding |
| **2. Boundary Gate** | `OPEG/1`, `EMA/1`, `SVA-GOV/1`, `@eyeoverthink/privacy-membrane` (`StreamSealGuard`) | *May this claim, skill, or token stream cross a trust boundary?* | Fail-closed `S0–S4` execution gate, format-agnostic receipt adapters (`SVA-ER/1`, `AER-1`), cross-token streaming PII/secret sealing, quorum & owner veto |
| **3. Epistemic Judge** | **`SVA-JEV/1`**, [`logic-chain-judge`](https://github.com/eyeoverthink/logic-chain-judge) | *Does an open-ended plan/brief trace back to its evidence, and which warnings require human judgment?* | Wilson 95% CI judge calibration (short + 15k-char padded controls), independent JEV voting (author self-vote excluded), verbatim `>= 12`-char quote enforcement, hidden planted-fake traps, zero-LLM `new_terms` scanner, replay-verified Ed25519 audit chain |

---

## 2. Empirical & Independent Verification Milestones

1. **Tri-Runtime Golden Conformance (`106/106` vectors, zero external dependencies):**
   - Verified byte-for-byte identically across **three independent implementations**:
     1. **Node.js V8** (`node:crypto` + V8 WebAssembly)
     2. **W3C Browser WebCrypto** (`crypto.subtle` + browser WebAssembly, zero Node imports)
     3. **Single-File Pure Java 25** (`SvaConformance.java` — pure-JDK Ed25519, RFC 8785 JCS, RFC 6962 Merkle, and a hand-written fuel-metered i32/f64/linear-memory WebAssembly VM)
2. **Independent Third-Party Protocol Interoperability (IETF `draft-zambo-aer1-26`):**
   - Two merged pull requests ([PR #1](https://github.com/eyeoverthink/sva-standard/pull/1), [PR #2](https://github.com/eyeoverthink/sva-standard/pull/2)) authored jointly with Brennan Zambo (`@zambodotdev`, author of IETF `AER-1`, kit `1.6.1`):
     - **Bidirectional Clock & Key-Binding Harness (`7/7 PASS`):** Maps `SVA-ER/1` explicit clock states (`attested | drift | unattested`) cleanly against `AER-1`'s explicit `absent` semantics without false downgrade or false upgrade; pinned LF vector blob SHA-256 (`796a5c87…`) preserved unchanged across releases.
     - **Format-Agnostic `OPEG/1` Gate Interop:** Verified a real served `AER-1` v0.4 receipt (`real-04.json`, live BTC/USD via CoinGecko) through `OPEG/1` `S4_COMMIT` via `evaluateOpeg1()`, while blocking tampered `price_usd` fail-closed.
3. **Empirical Epistemic Judge Measurements (`logic-chain-judge`, `321` automated tests, 0 pip deps):**
   - **Planted-Fake Detection:** `32/32` hidden fabricated/distorted claims caught (`0` falsely marked supported) alongside a zero-LLM deterministic scanner catching invented numbers and code identifiers absent from the ledger.
   - **Halo-Effect Mitigation:** Isolating checklist judging to one item per call reduced inter-judge disagreement from **`12/30` to `4/30`**.
   - **Context-Budget Bug Caught by Measurement:** Brief-vs-ledger auditing exposed a prompt truncation bug (brief writer seeing `0/566` design items); reserving a design floor raised brief checklist coverage from **`0.3–0.5/10` to `4.0–6.8/10`** while *shortening* briefs.
   - **Deterministic Chain Replay + `SVA-ER/1` Bridge:** `verify.py` deterministically replays `merge()` across all 16 sealed stage deltas to catch post-hoc ledger edits, and `run.py export-sva` exports verified runs as standard `SVA-ER/1` receipts and `OPEG/1` envelopes verified by `@eyeoverthink/ai-receipt`.
4. **Published Open-Source Ecosystem (All Apache-2.0, CI Green):**
   - **npm packages:** `@eyeoverthink/ai-receipt@1.3.0`, `@eyeoverthink/privacy-membrane@1.3.0` (including cross-token `StreamSealGuard`), `@eyeoverthink/skill-crystallizer@1.2.0`
   - **Companion repositories:** [`singlefile-gpt`](https://github.com/eyeoverthink/singlefile-gpt) (pure single-file Java transformer, `79/79` selftest), [`fmp1-mesh`](https://github.com/eyeoverthink/fmp1-mesh) (UDP/LoRa custody mesh + Python→Node `SVA-ER/1` bridge), [`fraymus-receipts`](https://github.com/eyeoverthink/fraymus-receipts) (formal WASM `FRYM` custom-section spec + 6 honest benchmarks reporting both reproduced and un-reproduced claims).

---

## 3. Reproducible 60-Second Verification

Anyone can reproduce the entire verification stack offline with standard toolchains:

```bash
# 1. Tri-runtime SVA conformance (106/106 across Node, WebCrypto, Pure Java 25) + AER-1 interop
git clone https://github.com/eyeoverthink/sva-standard && cd sva-standard
npm run conformance && npm test

# 2. Epistemic Judge test suite (321 tests, zero pip dependencies) + SVA-ER/1 bridge
git clone https://github.com/eyeoverthink/logic-chain-judge && cd logic-chain-judge
python3 -m unittest discover -s tests
```

Or open the **5 zero-backend browser playgrounds** (works with Wi-Fi disabled):
1. **Receipt Tamper Lab (`SVA-ER/1`):** [receipt-lab.html](https://eyeoverthink.github.io/sva-standard/receipt-lab.html)
2. **Privacy Membrane & `StreamSealGuard` Lab (`EMA/1`):** [membrane-lab.html](https://eyeoverthink.github.io/sva-standard/membrane-lab.html)
3. **Zero-Call Skill Induction Lab (`VSC/1`):** [skill-lab.html](https://eyeoverthink.github.io/sva-standard/skill-lab.html)
4. **OPEG/1 Gate Lab (`SVA-ER/1` + served `AER-1`):** [opeg-lab.html](https://eyeoverthink.github.io/sva-standard/opeg-lab.html)
5. **Calibrated Epistemic Judge Lab (`SVA-JEV/1`):** [judge-lab.html](https://eyeoverthink.github.io/sva-standard/judge-lab.html)

---

## 4. Explicit Honest Limits

- **No claim that model consensus equals truth:** Every `SVA-JEV/1` ballot and review verdict carries the mandatory label `"stability-signal-not-correctness"`.
- **Single-author calibration corpus:** The initial `known_answers.json` and `quality_cases.json` control sets were authored by one developer; expanding to independent multi-author benchmarks is an explicit next step.
- **Signature scope:** Ed25519 audit chains prove *key possession and post-signing integrity*, not that an external model honestly produced a given response or that local wall-clock time is trusted (hence explicit `clock.status = "unattested"`).
- **Deterministic vs. semantic boundary:** `new_terms` catches invented numbers and code identifiers with zero LLM calls, not subtle semantic paraphrasing.

---

## 5. Questions for Faculty Discussion

1. **Formalizing the Epistemic Judge:** Would the `SVA-JEV/1` calibration + planted-fake + verbatim-quote protocol (with empirical halo-effect and context-truncation measurements) be a strong fit for a workshop paper or senior/graduate systems capstone?
2. **Independent Control Corpora:** How best to design a multi-annotator benchmark corpus (with inter-annotator κ) for `SVA-JEV/1` calibration so standing thresholds are validated beyond single-author cases?
3. **Standards Track:** Given the working bidirectional interop with IETF `draft-zambo-aer1-26`, is there value in submitting a focused informational draft on format-agnostic execution gates (`OPEG/1`) or calibrated judge envelopes (`SVA-JEV/1`)?
