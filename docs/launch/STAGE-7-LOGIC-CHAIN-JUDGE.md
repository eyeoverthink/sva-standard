# Stage 7 Launch Kit — `logic-chain-judge` & `SVA-JEV/1` (Calibrated Epistemic Judge)

**Primary Repos & Demos:**
- Repo: https://github.com/eyeoverthink/logic-chain-judge (`v1.0.0`, Apache-2.0, 321 tests, Python 3.10+ stdlib only, zero `pip install`)
- Spec (`SVA-JEV/1`): https://github.com/eyeoverthink/sva-standard/blob/main/specs/SVA-JEV-1.md
- Live Zero-Backend Judge Lab (try in 10 seconds, 0 LLM calls): https://eyeoverthink.github.io/sva-standard/judge-lab.html

---

## 1. Hacker News (`Show HN`)

**Title:** `Show HN: Zero-dependency calibrated LLM judge with planted fakes and replay-verified Ed25519 chain`

**URL:** `https://github.com/eyeoverthink/logic-chain-judge`

**Top-level author comment:**
> I built a local-first Python 3.10+ (stdlib-only, zero pip dependencies, 321 tests) multi-role design pipeline and calibrated judge (`logic-chain-judge`) after getting burned by naive LLM-as-a-judge evaluations.
>
> Four specific failures we hit in real runs — and the mechanical gates that caught them:
>
> 1. **Short controls hide long-context failure:** A judge that passed short known-answer controls fell apart on 15,000-character briefs. Now calibration (`app/benchmark.py`, `app/quality.py`) tests both short and 15,000-char padded controls and requires a Wilson 95% CI lower bound strictly above the `66.7%` trivial baseline (`answered >= 30`, recall `>= 90%`, false-met `<= 10%`).
> 2. **Halo-effect judging:** Asking a judge to grade 10 checklist items in one call caused inter-judge disagreement on `12/30` items because its impression of the brief bled across items. Switching to one item per call (`ITEMS_PER_CALL = 1`) cut disagreement to `4/30`. Every `met: true` also requires an exact `>= 12`-char substring present in the document or it is mechanically rejected.
> 3. **Silent brief-vs-ledger hallucination:** During claim tracing (`app/claims.py`), 8 hidden planted fakes (5 fabricated + 3 distorted) are mixed into every real brief test (`32/32` planted fakes caught, `0` falsely supported), paired with a zero-LLM deterministic `new_terms` scanner that flags any number or code-style identifier in the brief absent from the source ledger.
> 4. **Context truncation bug caught by measurement:** Comparing brief scores against ledger scores exposed that warnings were crowding out design entries (brief writer saw `0/566` design items). Reserving a design floor raised checklist coverage from `0.3–0.5/10` to `4.0–6.8/10` while shortening briefs.
>
> Every stage is also Ed25519-signed and hash-chained, and `python3 run.py verify <id>` deterministically replays `merge()` across all sealed stage deltas to catch post-hoc ledger edits. `python3 run.py export-sva <id>` exports a verified run as an `SVA-ER/1` receipt verifiable by `@eyeoverthink/ai-receipt` or offline in the browser.
>
> **Try the deterministic judge gates in your browser (0 backend, 0 LLM calls):** https://eyeoverthink.github.io/sva-standard/judge-lab.html
>
> **Honest limits:** Votes are explicitly stamped `stability-signal-not-correctness` — consensus is never proof. And the initial control sets (`known_answers.json`, `quality_cases.json`) were written by one author; I opened Issue #1 inviting independent PRs to build a multi-author calibration corpus.

---

## 2. Reddit (`r/LocalLLaMA` & `r/MachineLearning`)

**Title:** `I built a zero-dependency calibrated LLM judge (Python stdlib, Ollama-ready) that injects hidden planted fakes and rejects hallucinated quotes — caught 32/32 fakes and cut judge disagreement from 12/30 to 4/30`

**Body:**
> Most LLM-as-a-judge setups have the same quiet failure modes: models grade their own claims, short toy tests hide 15k-char context rot, batching checklist items causes halo-effect grading, and nobody checks whether the judge's reasoning actually quotes the document.
>
> I open-sourced `logic-chain-judge` (Apache-2.0, Python 3.10+ stdlib only, zero `pip install`, works with local Ollama or API keys, **321 automated tests** passing on Linux & Windows):
>
> - **GitHub:** https://github.com/eyeoverthink/logic-chain-judge
> - **Live browser playground of the deterministic judge gates (0 backend, 0 API keys):** https://eyeoverthink.github.io/sva-standard/judge-lab.html
>
> ### What actually worked in measured runs (`docs/QUALITY.md` & `docs/REVIEW.md`)
> - **Planted-fake traps (`app/claims.py`):** 8 hidden fake claims (5 fabricated + 3 distorted) are injected into every brief audit. Measured runs caught **32/32 planted fakes (0 falsely supported)**, plus a zero-LLM `new_terms` scanner catches invented numbers and code identifiers absent from the source ledger.
> - **1-item-per-call judging (`app/quality.py`):** Batching checklist items caused `12/30` inter-judge disagreements (halo effect). Switching to 1 item per call dropped disagreement to **`4/30`**.
> - **Mandatory verbatim quotes:** A `met: true` verdict without an exact `>= 12`-char substring found in the document is mechanically rejected.
> - **Wilson 95% CI panel calibration (`app/benchmark.py`):** Judges must beat the `66.7%` trivial baseline on the *lower bound* of their 95% Wilson CI (on both short and 15,000-char padded controls) before earning a voting seat. Authors never vote on their own claims.
> - **Replay-verified Ed25519 audit chain (`app/verify.py`, `app/sva_bridge.py`):** `verify` deterministically replays `merge()` across every sealed stage delta to catch ledger tampering, and `export-sva` exports verified runs as standard `SVA-ER/1` receipts.
>
> ### Honest limits
> - Multi-model agreement is **not** proof of correctness (every review output is literally stamped `stability-signal-not-correctness`, and sub-80% items escalate to a human).
> - The initial calibration control sets (`known_answers.json` and `quality_cases.json`) were authored by one person — if you want to stress-test it with independent scenarios, there's an open community issue on the repo.
>
> Try it locally in 30 seconds (`git clone https://github.com/eyeoverthink/logic-chain-judge && python3 -m unittest discover -s tests`) or poke the live browser Judge Lab and tell me where you can break it.

---

## 3. Short X / Social Thread (4 Posts)

1. `Most LLM-as-a-judge evals fail silently: short controls hide 15k-char rot, batched checklists cause halo-effect grading, and judges pass items without quoting the text. Open-sourced logic-chain-judge (Python stdlib, 0 pip deps, 321 tests, Apache-2.0): https://github.com/eyeoverthink/logic-chain-judge`
2. `What empirical measurement caught: (1) Brief writer saw 0/566 design items -> fixing design floor jumped checklist coverage from 0.3-0.5/10 to 4.0-6.8/10. (2) 1-item-per-call judging cut judge disagreement from 12/30 to 4/30. (3) Hidden planted-fake traps caught 32/32 fakes (0 supported).`
3. `Every judge law is formalized as SVA-JEV/1 inside sva-standard v1.7.0 (106/106 golden vectors passing identically across Node V8, browser WebCrypto, and single-file Pure Java 25). Every ballot is stamped "stability-signal-not-correctness" — no pretending consensus equals proof.`
4. `Try all 6 deterministic judge gates live in your browser (0 backend, 0 LLM calls, works offline): https://eyeoverthink.github.io/sva-standard/judge-lab.html — and PRs are open on Issue #1 to expand the multi-author control corpus.`
