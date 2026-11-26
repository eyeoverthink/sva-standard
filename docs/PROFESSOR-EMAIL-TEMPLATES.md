# Faculty Outreach Emails & 3-Minute Office Hours Demo Guide

Copy-paste the template that matches your professor's area, replace `[Professor Last Name]` and `[Course/Topic]`, and send. Every claim below is verified by CI and reproducible in under 60 seconds.

---

## Template A — AI / Machine Learning / Evals Faculty

**Subject:** Question on calibrated LLM-as-a-judge evals + open conformance suite (`SVA-JEV/1`)

Hi Professor `[Last Name]`,

I'm a student in `[Course / SFSU CS]` working on verifiable trust boundaries for AI agents — specifically, how to combine cryptographic execution proofs with calibrated, falsifiable judging for natural-language plans.

In my open-source judge pipeline (`eyeoverthink/logic-chain-judge`, zero pip dependencies, 321 automated tests), measuring brief-vs-ledger fidelity exposed two concrete failure modes: a context-truncation bug (fixing it raised checklist coverage from `0.3–0.5/10` to `4.0–6.8/10`) and halo-effect judging (switching to one-item-per-call cut inter-judge disagreement from `12/30` to `4/30`), while hidden planted-fake controls caught `32/32` fabricated/distorted claims.

I formalized those deterministic judge rules as `SVA-JEV/1` inside an Apache-2.0 conformance suite (`106/106` golden vectors verified identically in Node V8, browser WebCrypto, and single-file Pure Java 25), with a 1-page summary and an offline browser Judge Lab here:
- **1-Page Faculty Brief:** https://github.com/eyeoverthink/sva-standard/blob/main/docs/PROFESSOR-BRIEF.md
- **Live Zero-Backend Judge Lab (works offline):** https://eyeoverthink.github.io/sva-standard/judge-lab.html

Would you have 15 minutes during office hours next week to take a quick look and tell me if this line of work could fit an independent study, workshop paper, or multi-annotator benchmark collaboration?

Best regards,  
Vaughn Scott  
GitHub: https://github.com/eyeoverthink

---

## Template B — Security / Cryptography / Distributed Systems Faculty

**Subject:** Open-source verifiable AI execution receipts (`SVA-ER/1`) + IETF `AER-1` interop

Hi Professor `[Last Name]`,

I'm a student in `[Course / SFSU CS]` building zero-dependency verification standards for autonomous AI agents (`eyeoverthink/sva-standard`, Apache-2.0): Ed25519-signed execution receipts with RFC 6962 odd-promotion Merkle proofs (`SVA-ER/1`), a fail-closed execution gate (`OPEG/1`), streaming PII egress sealing (`EMA/1`), and a replay-verified audit chain (`logic-chain-judge`).

All 7 wire specs pass a `106/106` golden conformance suite identically across Node.js V8, W3C Browser WebCrypto, and a single-file pure Java 25 verifier with a fuel-metered WebAssembly VM, and we recently completed two merged cross-format interoperability PRs with the author of IETF `draft-zambo-aer1-26` (wiring a real served `AER-1` v0.4 receipt through our `OPEG/1` gate).

Here is a 1-page technical overview and zero-backend browser demo (runs 100% client-side with zero external requests):
- **1-Page Faculty Brief:** https://github.com/eyeoverthink/sva-standard/blob/main/docs/PROFESSOR-BRIEF.md
- **Live Offline Playgrounds:** https://eyeoverthink.github.io/sva-standard/

Could I stop by office hours for 15 minutes next week to get your feedback on the threat model and whether this could fit a research project or capstone?

Best regards,  
Vaughn Scott  
GitHub: https://github.com/eyeoverthink

---

## Template C — Software Engineering / Capstone Advisor

**Subject:** Reproducible systems portfolio for `[Course / Capstone]` — verifiable AI agent standards

Hi Professor `[Last Name]`,

I've been building an Apache-2.0 open-source suite around verifiable local-first AI agents (`eyeoverthink/sva-standard` + `eyeoverthink/logic-chain-judge`), and I'd love your advice on scoping it toward a capstone or faculty-guided project.

Everything is zero-dependency, CI-verified across Linux/Windows, and testable in under a minute — `106/106` tri-runtime conformance vectors (Node, WebCrypto, Java 25), `321` Python judge tests, 3 published npm packages, 2 merged third-party IETF `AER-1` interop PRs, and 5 offline browser playgrounds.

Here is a 1-page summary with exact reproduction commands and honest limits:
- **1-Page Faculty Brief:** https://github.com/eyeoverthink/sva-standard/blob/main/docs/PROFESSOR-BRIEF.md
- **Live Browser Playgrounds:** https://eyeoverthink.github.io/sva-standard/

Do you have 15 minutes during office hours next week to discuss next steps?

Best regards,  
Vaughn Scott  
GitHub: https://github.com/eyeoverthink

---

## 3-Minute Office Hours Live Demo Script (Works Offline / Bad Wi-Fi)

Open `https://eyeoverthink.github.io/sva-standard/` on your laptop before walking in (it works with Wi-Fi turned off!).

1. **Minute 1 — Layer 1 (`receipt-lab.html`):**
   - Click **Mint Receipt**, then click **Alter 1 byte of deliverable** and **Strip IN_CLOUD entry**.
   - Say: *"Instead of trusting an agent's log, the verifier checks Ed25519 signatures, RFC 6962 Merkle proofs, and entry completeness client-side."*
2. **Minute 2 — Layer 2 (`opeg-lab.html`):**
   - Click **1. Try DIRECT_INFERENCE Bypass** (blocked fail-closed), then click **4. Unlock with Served AER-1 v0.4 Receipt** (passes with Brennan Zambo's real IETF `AER-1` receipt), then **5. Tamper price_usd** (blocked!).
   - Say: *"The gate is format-agnostic — an external IETF draft author wired his receipt format through our gate in PR #2."*
3. **Minute 3 — Layer 3 (`judge-lab.html`):**
   - Click **2. Deceptive 72% Judge** (Wilson 95% CI lower bound `0.560 <= 0.667` blocks it), **4. Hallucinated Quote** (mechanically rejected), and **6. Invented Number/ID + Missed Fake** (`9999` and `invented_helper_v2` caught with 0 LLM calls).
   - Say: *"Where outputs are natural language instead of code, we never claim consensus equals truth — every verdict is labeled `stability-signal-not-correctness`, gated by Wilson CI calibration, verbatim quotes, and hidden planted fakes."*
4. **Close with 1 clear question:** *"What would you tighten first if we wanted to turn the `SVA-JEV/1` judge measurements into a short workshop paper or independent study?"*
