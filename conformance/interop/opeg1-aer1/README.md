# OPEG/1 + AER-1 Wiring Run

A complete, reproducible run of the OPEG/1 S4 commit gate (specs/OPEG-1.md,
Section 4, as it stands on main at 6283b85) with `receiptFormat: "aer-1"`:
a real AER-1 v0.4 receipt (IETF draft-zambo-aer1-26) wired through the
format-agnostic adapter boundary Vaughn designed in v1.5.0, so either an
SVA-ER/1 or an AER-1 receipt can unlock S4_COMMIT.

## The receipt

A production Zambo receipt, taken from the served AER-1 conformance corpus
(kit 1.6.1, evaluated set digest
`sha256:4ea44dc07125a6f9b7fa472450a30fb56265771cfe87b1772a02b03d1fc166f2`),
vector `base/test-vectors/valid/real-04.json`, file SHA-256
`45c6af65806ad125d9ac33da9e13c737d89e1f2efde5c662cd7baa2db3ab51f8`:

- Receipt id: `c17b436d-0d9e-48a1-a5de-08dc80a9767e`
- Tool: `live_price` v4.0.0, scope `public`; created `2026-10-17T15:04:05.000Z`
- `provenance_class`: `EXECUTED BY ZAMBO`; schema `0.4`; `verification_status`: `verified`
- `output_hash`: `sha256:c92e4cfdc2a00d2914d6d5c596d0936e6bfdba522a125467a08ef6ebce5974ca`
- `metadata_hash`: `sha256:8502f3dfb695d08d986ae9b51b7d86e278d6911bfe0dbfda92a57679037029da`
- Committed outputs (inside `canonical_bytes`):
  `{"pair":"BTC_USD","price_usd":97412.55,"source":"CoinGecko","status":"complete"}`

This vector was chosen because its committed `outputs` is a JSON object,
which is what the OPEG/1 envelope requires of `sanitizer.rSan`.

## The wiring

`envelope.json` is the S4_COMMIT envelope as wired:

- `sanitizer.rSan` is set to the receipt's committed `outputs` object, so the
  value the gate commits to is byte-for-byte the value the receipt binds.
- `sanitizer.rSanSha256` = `SHA-256(JCS(rSan))` =
  `153c596b951df51e67087b98515de359a48894c2c826f9056b0934db47c6ee24`,
  recomputed in this run.
- `receiptFormat: "aer-1"`, and the receipt is embedded as `receipt`.

## The gate, rule by rule (specs/OPEG-1.md Section 4, main HEAD)

OPEG/1 ships no packaged gate function for the `"aer-1"` profile:
`evaluateOpegGate` in the playground hard-codes the SVA-ER/1 path. So this
run composes the gate faithfully from the spec text, and says so rather than
pretending a packaged gate exists. `verify-opeg1-aer1.mjs` performs:

1. `spec === "opeg/1"` and `state === "S4_COMMIT"`.
2. `mode === "EXECUTE_AND_RECEIVE"`.
3. `sourcePriority` begins with `"runtime_receipt"`.
4. `sanitizer.status === "SUCCESS"`, `rSan` a non-null object, and
   `rSanSha256 === SHA-256(UTF8(JCS(rSan)))`.
5. The `"aer-1"` leg:
   1. The receipt is evaluated by `evaluateAer1V04`, the AER-1 v0.4
      evaluator already in this repo at
      `conformance/interop/aer1-svaer1/verify-interop.mjs`: v0.4 core
      fields, `output_hash` over the raw canonical bytes, payload version
      agreement, `issuer_claims` provenance binding, and the Section 3.1
      `metadata_hash` block.
   2. The outputs binding from the clarified rule text on main: inside the
      decoded `canonical_bytes` payload, `SHA-256(UTF8(JCS(payload.outputs)))`
      equals `sanitizer.rSanSha256` (the direct payload match form; the
      explicit `payload.outputs.rSanSha256` field form is also accepted).
   3. The verdict preserves AER-1's explicit absent readings as
      `receiptOutcome: { outcome: "verified", clockAttestation: "absent", issuerKeyBinding: "absent" }`
      instead of collapsing them into a boolean.

## Verdict

`verdict.json` is the runner's captured output on `envelope.json`:

- Gate: **pass** (exit 0). All six checks ok.
- `receiptOutcome`: `{ "outcome": "verified", "clockAttestation": "absent", "issuerKeyBinding": "absent" }`.

## Negative control

`envelope-tampered.json` is the same envelope with one change:
`sanitizer.rSan.price_usd` altered from `97412.55` to `1.00`, digest left
untouched. The receipt itself still verifies (rule 5.1 ok, binding 5.2 ok,
because the receipt was never touched), but rule 4 fails:
`SHA-256(JCS(rSan))` becomes
`a87eb698daaefdab55b923d3896721df8f2c102e897aefcc4e2494d9277d16ce`, which no
longer equals the committed `rSanSha256`. Gate: **blocked** (exit 1).
Captured in `verdict-tampered.json`. That is the seam doing its job: swap the
sanitized payload after the fact and S4 stays closed, even with a genuine
receipt in hand.

## Independent recompute

The AER-1 side was also recomputed independently of this repo's code, in
Python, straight from draft-zambo-aer1-26 Section 3.1: `output_hash` and
`metadata_hash` both reproduce the receipt's values exactly
(`sha256:c92e4cfd...` and `sha256:8502f3df...`), and the payload version
agreement and `issuer_claims.provenance_class` binding hold. Two
implementations, one verdict.

## Reproduce

```sh
node conformance/interop/opeg1-aer1/verify-opeg1-aer1.mjs            # gate: pass, exit 0
node conformance/interop/opeg1-aer1/verify-opeg1-aer1.mjs conformance/interop/opeg1-aer1/envelope-tampered.json
                                                                      # gate: blocked, exit 1
```

## Scope

By design, the AER-1 profile carries no issuer authentication: core AER-1
does not bind an issuer key in-band, so the verdict reports
`issuerKeyBinding: "absent"` rather than claiming an authentication it did
not perform. This gate checks that a receipt is internally intact and bound
to the envelope; a deployment that requires proof of who issued a receipt
must layer that check on top.

This directory is additive only. The frozen 7-case interop file
`conformance/interop/aer1-svaer1/vectors.json` is untouched, at its pinned
SHA-256 `796a5c8783b9927b41682bf35acda74517ccafd9b16fcda52003330bf19dfcf76`,
and the repo suite (`npm test`) passes with this directory in place
(7 pass, 0 fail, 1 environment skip for the Java runtime).
