# Stage 2 Launch Kit — `@eyeoverthink/skill-crystallizer` + Skill Binder Lab (Weeks 3–4)

> **Launch Guardrails Verified:** Zero bio/sci-fi lore · `<10s` 0-GPU CLI + live $0 static browser playground · 100% Apache-2.0 local-first · Explicit scope limits (numeric/parameterized tasks only; prose synthesis stays outside scope).

---

## T-24h Pre-Flight Checklist
- [ ] Verify live playground in incognito tab: https://eyeoverthink.github.io/sva-standard/skill-lab.html
- [ ] Verify `<10s` 0-GPU CLI on both valid task & sales-tax near-miss trap:
  ```bash
  node packages/skill-crystallizer/bin/skill-crystallizer.js
  node packages/skill-crystallizer/bin/skill-crystallizer.js "A \$200 laptop is 20% off, then 8% sales tax is added. What is the final price?"
  ```
- [ ] Confirm `npm pack --dry-run` in `packages/skill-crystallizer/` (5 files, 10.5 kB, 0 deps).

---

## T+0h — 90-Second Own-Voice YouTube Demo Script

- **0:00–0:15 (Hook):** "Why pay an LLM to solve the same structured task 1,000 times — and why do regex routers silently misfire on near-misses? Here's `@eyeoverthink/skill-crystallizer`: zero dependencies, zero LLM calls, running live in your browser right now." *(Screen: https://eyeoverthink.github.io/sva-standard/skill-lab.html)*
- **0:15–0:45 (Live Induction + Zero-Call Routing):** "Give it 3 verified positive examples and 1 negative counterexample. It induces a deterministic binder in under 1 millisecond, validates it with leave-one-out cross-validation (3/3 holdouts pass), and routes fresh prompts like '$240 coat, 25% then 10% off' straight to `$162.00` at 0 LLM calls."
- **0:45–1:15 (Near-Miss Traps):** "Now try to trick it. Click the Sales Tax trap — '20% off, then 8% sales tax is added' — same 3 numbers, completely different math. The positional wording gate refuses it immediately (`sales after % #2`, `tax after % #2`). Try the Tip trap: refused. Try adding an extra quantity ('2 jackets'): number-shape mismatch (`1,2,1` vs `1,2,0`), refused — safely falling back to your agent loop."
- **1:15–1:30 (Open Challenge):** "Open the static playground link below — zero backend, zero sign-up — and try to craft a near-miss prompt that tricks the binder into misrouting. Post your breaking prompt in the issue tracker and I'll patch the induction gate within 48 hours."

---

## T+0h — Show HN Submission

**Title:** `Show HN: Zero-LLM skill binder induction with positional near-miss refusal (static lab)`

**Immediate First Comment (Post within 60 seconds):**
> Hi HN — when local AI agents repeatedly solve structured parameterized tasks, calling an 8B/70B model every time is slow and expensive, while naive regex/tool routers silently misroute near-miss prompts (e.g., routing "20% off + 8% sales tax" into a "20% off + 10% off" function because both have `$price`, `%1`, `%2`).
>
> `@eyeoverthink/skill-crystallizer` is a zero-dependency ES module (12.7 kB) that induces deterministic argument binders from positive + negative examples using leave-one-out cross-validation and positional wording gates around every numeric slot — with **0 LLM calls**.
>
> **Try it in <10 seconds (0 GPU, 0 backend):**
> - Live offline-capable browser lab: https://eyeoverthink.github.io/sva-standard/skill-lab.html
> - Zero-install CLI inside repo:
>   ```
>   node packages/skill-crystallizer/bin/skill-crystallizer.js
>   node packages/skill-crystallizer/bin/skill-crystallizer.js "A $200 laptop is 20% off, then 8% sales tax is added. What is the final price?"
>   ```
>
> **Honest Limits:**
> - Currently proven on structured numeric/parameterized tasks where arguments appear explicitly in the prompt; open-ended prose synthesis and multi-hop symbolic algebra are explicitly out of scope and fall through to a verified agent loop.
> - Intentionally conservative: unseen wording near a numeric slot triggers safe refusal (`novelWording.length > 0`) rather than risking silent misrouting. That trades recall for precision.
>
> **Open Challenge:** Try to craft a near-miss prompt in `skill-lab.html` that tricks the sequential-discount binder into routing when it shouldn't. I'll merge fixes for real bypasses within 48 hours.

---

## T+4h — 5-Post X Receipts Thread

1. **Post 1 (Hook + Playground):** Stop burning LLM tokens on repeated structured tasks — and stop letting naive routers misfire on near-misses. Try `@eyeoverthink/skill-crystallizer` live in your browser (0 backend, 0 LLM calls): https://eyeoverthink.github.io/sva-standard/skill-lab.html
2. **Post 2 (Terminal Clip):** 1 CLI command, 0 installs: valid fresh prompt routes in <1 ms (`routed: true, modelCalls: 0, answer: 162`); sales-tax near-miss with the exact same number shape (`$`, `%`, `%`) returns `routed: false`. *[Attach 10s CLI clip]*
3. **Post 3 (How It Works):** Induces typed slots + unit tags (`$`, `%`) + positional context words before/after each slot, verifies 3/3 leave-one-out holdouts, and refuses any fresh prompt introducing novel wording adjacent to a numeric slot.
4. **Post 4 (Bug We Fixed First):** Earlier audit caught `$1,200` splitting into `1` and `200`, and `v * 100` matching unrelated integers. Both fixed and locked down with deterministic tests.
5. **Post 5 (Open Challenge):** Can you craft a near-miss prompt in `skill-lab.html` that fools the sequential-discount binder into returning `routed: true` on the wrong math? Reply with the prompt — breaking edge cases patched in 48h.

---

## T+24h — Native Markdown Post (`r/LocalLLaMA` / `r/programming`)

**Title:** `Zero-LLM deterministic skill routing: how we induce argument binders from 3 examples and refuse near-miss traps in <1 ms (Apache-2.0, zero deps)`

*(Explain the exact problem on local 7B/8B models — 11–20s per verified answer vs <1 ms once crystallized — show the exact JSON output for valid vs sales-tax/tip/quantity traps, clearly state the numeric-only scope limit, and link both the static playground and source module.)*

---

## T+72h — 60-Second YouTube Short Template
- Showcase the cleverest near-miss bypass submitted by a reader, show the 10-line induction gate patch + regression test, and verify it now returns `SAFE REFUSAL` in `skill-lab.html`.
