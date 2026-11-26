# Multi-Channel Launch Scripts — Reddit, Show HN & 90-Second Demo Video

Everything below follows the 5 Anti-Hype Guardrails: zero lore, `<10s` browser or `npx` verification upfront, explicit honest limits, and factual attribution.

---

## 0. 5-Minute Pre-Launch Checklist

1. Pin your top 5 clean repos on `https://github.com/eyeoverthink`:
   - `sva-standard`
   - `singlefile-gpt`
   - `fmp1-mesh`
   - `fraymus-receipts`
   - `babel-engine`
2. Space launches **1 per week** (Tue–Thu, **8:00–10:00 AM PT**):
   - Week 1: `singlefile-gpt` ([STAGE-1-SINGLEFILE-GPT.md](STAGE-1-SINGLEFILE-GPT.md))
   - Week 2: `@eyeoverthink/privacy-membrane@1.3.0` ([STAGE-3-PRIVACY-MEMBRANE.md](STAGE-3-PRIVACY-MEMBRANE.md))
   - Week 3: `fmp1-mesh` ([STAGE-4-FMP1-MESH.md](STAGE-4-FMP1-MESH.md))
   - Week 4: `sva-standard` + `AER-1` interop story (below)
   - Week 5: `fraymus-receipts` ([STAGE-5-FRAYMUS-RECEIPTS.md](STAGE-5-FRAYMUS-RECEIPTS.md))
3. Stay active in comments for the first 2 hours; answer every critique calmly and factually.

---

## 1. Ready-to-Post Reddit Draft (`r/LocalLLaMA` / `r/programming` / `r/netsec`)

**Title:**
> I built zero-dependency, offline-verifiable execution receipts and a streaming split-token PII guard for local AI agents (live browser labs, 0 backend)

**Body:**
```markdown
One thing that kept bugging me when running local AI agents (Ollama / multi-agent loops) is that you have to take the agent's word for what it actually ran — and if it calls a cloud fallback, naive regex filters miss secrets split across streaming tokens (`"sk-"` in chunk 1, `"ant-..."` in chunk 2) or digit-squeezed SSNs (`123456789`).

So I extracted our core verification layer into a zero-dependency Apache-2.0 spec & conformance suite (**[eyeoverthink/sva-standard](https://github.com/eyeoverthink/sva-standard)**) with **4 static browser labs** (0 backend servers, 0 external CDNs — turn off your Wi-Fi and test them):

- **OPEG/1 Execution Gate Lab:** https://eyeoverthink.github.io/sva-standard/opeg-lab.html — refuses `DIRECT_INFERENCE` until a runtime receipt verifies. Works with **both** our Ed25519 `SVA-ER/1` receipts *and* real served IETF `draft-zambo-aer1-26` (`AER-1` v0.4) receipts (co-authored via PR #1 & PR #2 with Brennan Zambo).
- **Privacy Membrane & Streaming Guard Lab:** https://eyeoverthink.github.io/sva-standard/membrane-lab.html — test cross-token split-secret sealing (`StreamSealGuard`), digit-squeezed SSN egress blocks, and zero-width Unicode injection evasion.
- **Receipt Tamper Lab:** https://eyeoverthink.github.io/sva-standard/receipt-lab.html — mint an Ed25519 + RFC 6962 Merkle receipt in-browser and run 6 one-click cheat attacks.
- **Zero-Call Skill Binder Lab:** https://eyeoverthink.github.io/sva-standard/skill-lab.html — induce a pure routing binder from 3 solved examples with 0 LLM calls and test near-miss traps.

**Try it in 10 seconds with 0 GPU:**
```bash
npx @eyeoverthink/privacy-membrane stream-demo
npx @eyeoverthink/skill-crystallizer
```
Or clone the repo and run `npm test` — **96/96** golden vectors pass identically across **Node.js V8**, **W3C Browser WebCrypto** (0 `node:crypto`), and a **single-file pure Java 25** runner with its own fuel-metered WASM VM (~2 seconds total).

**Honest limits:**
- Proves cryptographic integrity and completeness of what the signing host recorded — cannot prevent a compromised host from lying *before* signing.
- Deterministic pattern sealing catches structured PII/secrets at <1 ms; unstructured person/org names still need a local NER pass.
- Verification covers deterministic numeric/code/WASM execution, not subjective prose quality.

Would love feedback or attempts to break the browser labs!
```

---

## 2. Show HN / Dev.to Story Draft — *"How a Naming Collision Turned Into Two Merged Interop PRs"*

*(Send a quick courtesy ping to `@zambodotdev` before posting this specific angle.)*

**Title:**
> Show HN: Turning an IETF naming collision into two merged cross-format AI receipt interop PRs

**Key Beats:**
1. Published our local-first execution receipt spec under the working name `AER/1` — and quickly heard from Brennan Zambo (`@zambodotdev`), author of the active IETF Internet-Draft `draft-zambo-aer1-26` (`AER-1`, 143-vector corpus).
2. Instead of arguing over a name or papering over differences:
   - Renamed our format cleanly to **`SVA-ER/1`** (`application/sva-er+json`).
   - Added a factual Section 7 comparison table mapping the **5 structural differences** (Ed25519 trust root vs keyless core, bundled mission receipt vs single-call record + commitment, RFC 6962 odd-node promotion vs odd-level duplication, JCS vs AER-1 canonical bytes, explicit `attested | drift | unattested` clocks).
   - Adopted named verification outcomes (`verified | not_checked | verification_failed | absent`) so missing checks never collapse into a boolean.
3. Built a bidirectional interop harness pinned to `kit 1.6.1` (`conformance/interop/aer1-svaer1/`):
   - **PR #1:** `@zambodotdev` added `interop-06` (`aer-04`) and `interop-07` (`aer-05`) directly in our schema (**7/7 PASS**, byte-exact pinned SHA-256).
   - **PR #2:** `@zambodotdev` wired a real served `AER-1` v0.4 receipt (`valid/real-04.json`, live BTC_USD price) straight through our format-agnostic **`OPEG/1`** pre-answer execution gate (`conformance/interop/opeg1-aer1/`).
4. **Try both formats side-by-side right now in your browser (0 backend):** https://eyeoverthink.github.io/sva-standard/opeg-lab.html

---

## 3. 90-Second YouTube / X / LinkedIn Demo Video Script

**Format:** 1080p clean screen recording + calm voiceover. No intro logos, no background music hype, no slides.

| Time | On Screen | Voiceover |
|---|---|---|
| **0:00–0:15** | Open `https://eyeoverthink.github.io/sva-standard/opeg-lab.html` with DevTools Network tab open (showing 0 external calls). Click **Button 1 (`Try DIRECT_INFERENCE Bypass`)**. | *"Every AI agent claims it ran the math. Here's a zero-backend execution gate running completely offline in the browser. First, the agent tries to answer by direct inference — blocked immediately at S2."* |
| **0:15–0:35** | Click **Button 2 (`Run EP3 Check + Sign SVA-ER/1`)** → green `S4_COMMIT UNLOCKED`. Then click **Button 3 (`Tamper SVA-ER/1 R_san`)** → red `TAMPER CAUGHT`. | *"Now it runs the numerical check locally, sanitizes the output, signs an Ed25519 SVA-ER/1 receipt, and unlocks S4. Flip a single minus sign after signing — caught immediately before commit."* |
| **0:35–0:55** | Click **Button 4 (`Unlock with Served AER-1 v0.4 Receipt`)** → green `S4_COMMIT UNLOCKED (receiptFormat=aer-1)`. Click **Button 5 (`Tamper AER-1 R_san`)** → red `TAMPER CAUGHT AT RULE 4`. | *"The gate is format-agnostic. Here's a real served IETF AER-1 v0.4 receipt unlocking the exact same gate while explicitly preserving `clockAttestation: absent`. Tamper the price — blocked at Rule 4 even though the receipt stays intact."* |
| **0:55–1:15** | Switch to `membrane-lab.html`. Click **Simulate Split-Token LLM Stream** (`sk-` + `ant-...`, `123-` + `45-6789`) → `STREAM CLEAN`. Click **Simulate Egress Leak** → `EGRESS BLOCKED`. | *"And for outbound privacy: streaming LLMs split API keys across tokens. `StreamSealGuard` buffers chunk boundaries so split keys and SSNs never leak mid-stream — and blocks digit-squeezed leaks before they hit the socket."* |
| **1:15–1:30** | Switch to terminal. Run `npm test` → **96/96** passing across Node V8, W3C WebCrypto, and Single-File Java 25 in ~2 seconds, 0 GPU. | *"Zero runtime dependencies, Apache-2.0, 96 golden vectors passing across Node, WebCrypto, and single-file Java in two seconds. Links in the description."* |

**Distribution tip:** Upload the 90-second MP4 natively on X and LinkedIn (link in the first reply), upload to YouTube with chapters matching the timestamps above, and drop the YouTube link in a follow-up comment on Reddit (keeping the main Reddit link pointed at the repo or live playground).
