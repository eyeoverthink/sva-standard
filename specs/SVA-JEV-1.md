# SVA-JEV/1 — Calibrated Epistemic Judge & Evidence-Traced Review Specification

**Status:** Draft Standard (`sva-jev/1`, SVA Standard `v1.7.0`)  
**Author:** Vaughn Scott (`eyeoverthink`)  
**Reference Implementation:** [`eyeoverthink/logic-chain-judge`](https://github.com/eyeoverthink/logic-chain-judge) (`app/benchmark.py`, `app/jev.py`, `app/quality.py`, `app/claims.py`, `app/verify.py`, `app/sva_bridge.py`)  
**Conformance Suite:** `conformance/v1/vectors.json` (`suite: "jev1"`, 10 deterministic golden vectors verified identically in Node V8, W3C Browser WebCrypto, and Single-File Pure Java 25)

---

## 1. Scope and Honest Boundary

`SVA-ER/1` and `OPEG/1` verify **deterministic execution and gate binding** (hashes, signatures, Merkle inclusion, WASM execution, sanitized numeric/structured outputs). They explicitly do **not** verify whether open-ended natural-language prose, architectural briefs, or multi-agent design proposals are faithful to their source evidence.

`SVA-JEV/1` specifies the **deterministic epistemic judge gate** that audits natural-language outputs and multi-model reviews **without pretending model agreement equals cryptographic truth**.

Every `sva-jev/1` envelope MUST carry:

```json
{
  "spec": "sva-jev/1",
  "semantics": "stability-signal-not-correctness"
}
```

Any envelope missing `spec === "sva-jev/1"` or `semantics === "stability-signal-not-correctness"` MUST be rejected fail-closed.

---

## 2. Deterministic Profile 1: Judge Panel Calibration (`mode: "calibration"`)

Models MUST NOT receive a voting or judging seat merely by being configured. They MUST pass blind known-answer control scenarios (including long-document padded controls to detect context-length degradation).

### Required Fields
- `answered` (non-negative safe integer)
- `total` (positive safe integer, `answered <= total`)
- `right` (non-negative safe integer, `right <= answered`)
- `realFound` (non-negative safe integer)
- `realTotal` (positive safe integer, `realFound <= realTotal`)

### Wilson 95% Confidence Interval & Standing Rule
Unanswered control items count as wrong (`p = right / total`) so a candidate cannot inflate accuracy by abstaining on hard cases. With `z = 1.96`:

$$\text{denom} = 1 + \frac{z^2}{n}, \quad \text{center} = \frac{p + \frac{z^2}{2n}}{\text{denom}}, \quad \text{margin} = \frac{z\sqrt{\frac{p(1-p)}{n} + \frac{z^2}{4n^2}}}{\text{denom}}$$

$$\text{low} = \max(0, \text{center} - \text{margin}), \quad \text{found} = \frac{\text{realFound}}{\text{realTotal}}$$

A candidate earns `"calibrated"` standing if and only if ALL three conditions hold:
1. `answered >= 30` (minimum sample size)
2. `low > 2 / 3` (lower bound of 95% Wilson CI strictly exceeds the trivial "clear every warning" baseline)
3. `found >= 0.9` (at least 90% recall on real issues)

If any condition fails, standing is `"uncalibrated"` and calibration check returns `ok: false`.

---

## 3. Deterministic Profile 2: Independent JEV Consensus & Author Exclusion (`mode: "vote"`)

Reviewers vote independently on warnings without seeing other ballots and MUST NEVER vote on claims they authored.

### Required Fields
- `author` (non-empty string identity, e.g., `"anthropic:claude-sonnet"`)
- `ballots` (JSON object mapping `voterId -> choice`)
- `declaredDecision` (`"settled"` or `"escalate_human"`)

### Valid Choices & Outcome Mapping
- Valid choices: `"decide"`, `"noise"`, `"settled"` (any other value is treated as abstention).
- Outcome mapping:
  - `"settled"` and `"noise"` map to `"clear"` (no human intervention required).
  - `"decide"` maps to `"human"` (requires human resolution).

### Tallying Rules
1. Exclude any ballot where `voterId === author` (**author self-vote exclusion**).
2. Let `valid` be all remaining ballots with a choice in `{"decide", "noise", "settled"}`.
3. If `valid.length < 2`, the computed decision MUST be `"escalate_human"`.
4. If `clearCount / valid.length >= 0.8`, the computed decision is `"settled"`.
5. Otherwise (whether `humanCount / valid.length >= 0.8` or the panel is split below `80%`), the computed decision MUST be `"escalate_human"`.
6. Verification passes (`ok: true`) if and only if `declaredDecision === computedDecision`. Any attempt to declare `"settled"` with an author self-vote, fewer than 2 independent voters, or `< 80%` agreement MUST be rejected fail-closed.

---

## 4. Deterministic Profile 3: Verbatim Quote Enforcement (`mode: "quote_check"`)

A checklist judge MUST NOT mark a requirement `met: true` without supplying an exact substring present in the evaluated document.

### Normalization (`flat(text)`)
1. Remove markdown syntax characters: `*`, `_`, `` ` ``, `#`, `>`
2. Normalize typography: `’` -> `'`, `“` and `”` -> `"`, `–` and `—` -> `-`
3. Collapse all whitespace runs (`\s+`) to a single ASCII space (`0x20`), trim leading/trailing space, and lowercase.

### Enforcement Rules
- Required fields: `document` (string), `verdicts` (non-empty array of `{ id, met, quote }`), `declaredMetCount` (non-negative safe integer).
- Let `plain = flat(document)`.
- For each verdict:
  - `id` must be a non-empty string and `met` must be a boolean.
  - If `met === true`, the verdict is accepted ONLY if `typeof quote === "string"`, `flat(quote).length >= 12`, and `plain.includes(flat(quote))`. Otherwise `rejectedQuotes` is incremented.
- Verification passes (`ok: true`) if and only if `rejectedQuotes === 0` AND `acceptedMetCount === declaredMetCount`.
- Split items across multiple judges MUST be reported as an explicit `[low, high]` range rather than rounded to a point estimate.

---

## 5. Deterministic Profile 4: Planted-Fake Trap Gate & Zero-LLM `new_terms` Scanner (`mode: "claim_trace"`)

When tracing a synthesized brief back to a provenance-tagged ledger, `SVA-JEV/1` combines a **live control trap** with a **zero-LLM deterministic invention scanner**.

### Required Fields
- `ledgerTexts` (non-empty array of strings)
- `briefText` (string)
- `plantedFakes` (non-empty array of `{ id, verdict }`, where `verdict` is `"supported" | "unsupported" | "contradicted"`)
- `allowNewTerms` (optional boolean, default `false`)

### Gate Rules
1. **Planted-Fake Trap Gate:** Every hidden planted fake MUST be caught (`verdict !== "supported"`). If any planted fake has `verdict === "supported"`, the entire claim-trace audit MUST be rejected fail-closed (`ok: false`).
2. **Deterministic Zero-LLM `new_terms` Scanner:** Extract all candidate factual/technical tokens from `briefText` and the combined `ledgerTexts`:
   - **Numeric tokens:** multi-digit integers or decimal numbers matching `\b\d+(?:\.\d+)*\b` where length `>= 2` or the token contains `.`
   - **Code-style identifiers:** snake_case (`[A-Za-z]+_[A-Za-z0-9_]+`) or camelCase (`[a-z]+[A-Z][A-Za-z0-9]*`) identifiers
   - Compare case-insensitively (ASCII lowercase). Any extracted token present in `briefText` that does NOT appear in `ledgerTexts` is added to `newTerms`.
   - If `allowNewTerms !== true` and `newTerms.length > 0`, verification MUST fail closed (`ok: false`).

---

## 6. Bridge to `SVA-ER/1` and `OPEG/1`

A completed Logic Chain run whose Ed25519 hash-linked audit chain passes deterministic `merge()` replay verification (`app/verify.py`) can be exported via `app/sva_bridge.py` (`python3 run.py export-sva`) as:
- A conformant **`SVA-ER/1`** receipt binding `deliverableSha256 = SHA-256(JCS(runSummary))`, RFC 6962 Merkle proofs over every sealed stage, and explicit `clock.status: "unattested"` honesty.
- A conformant **`OPEG/1` `S4_COMMIT`** envelope (`receiptFormat: "sva-er/1"`) binding `sanitizer.rSan` to the verified run commitment.

---

## 7. Honest Limits

1. **Calibration is relative to the control corpus:** Wilson CI standing proves a judge outperforms the trivial baseline on the pinned control set; it does not prove universal infallibility on out-of-distribution domains.
2. **Consensus is not truth:** Even 5/5 calibrated providers agreeing at 100% is explicitly labeled `"stability-signal-not-correctness"`.
3. **Quote presence is necessary, not sufficient:** `flat(quote)` guarantees the judge cited real text from the document, preventing pure hallucination, while human review remains required for semantic judgment.
4. **Deterministic `new_terms` catches invented numbers and identifiers, not subtle prose paraphrasing:** That is why `SVA-JEV/1` pairs `new_terms` with planted-fake claim tracing.
