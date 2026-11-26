# Cross-Agency Immune System Demo (`vsc-revoke/1`)

Zero-dependency, zero-GPU live reproduction of the Stage 5 Cross-Agency Immune System over **4 real local HTTP agencies (`A, B, C, D` on `127.0.0.1`)**.

## Run in < 1 Second

```bash
node demos/immune-mesh/run-demo.mjs
```

## What It Proves Live Over HTTP

1. **1-Hop Crash Containment (`A → B → C`):** Agency A hits divide-by-zero in a signed `vsc/1` WASM skill, signs a `vsc-revoke/1` tombstone carrying counterexample `[10000, 8, 0]`, and posts it to B. B verifies the signature, locally executes the counterexample in the fuel-metered WASM VM, reproduces the trap, quarantines the skill, increments `repConfirmed[A]`, and relays (TTL-clamped) to C, which independently reproduces and quarantines it.
2. **Wrong-Output Containment & Hash Quarantine:** Agency A broadcasts a signed counterexample `[10000, 20]` (observed `9980 != 8000`) for `wasm_buggy_discount`. Both B and C reproduce the wrong output locally, quarantine the `codeSha256`, and reject future re-import attempts of that hash.
3. **Byzantine Auto-Demotion (`D → B, C`):** Malicious trusted peer D submits 2 irreproducible false-flag revocations targeting healthy `wasm_discount_cents`. Both B and C run the counterexamples locally, confirm the skill is healthy (`falseQuarantines: 0`), keep it `active`, and auto-demote D (`trusted → known`), rejecting D's 3rd message with HTTP `403`.
4. **Outbound Privacy Membrane & Fail-Closed Admission:** Raw PII (`SSN`) inside an advisory note is blocked by `@eyeoverthink/privacy-membrane` before any byte leaves the socket, and unsigned `vsc/1` capsules (`sig: null`) are rejected fail-closed.

## Honest Limits
- Hash quarantine blocks exact `codeSha256` bytes; recompiled binaries with a different hash land on probation rather than being pre-blocked.
- This standalone demo exercises deterministic WASM counterexample reproduction at 0 GPU calls; open-ended LLM semantic fault reproduction (measured at 5 local Ollama calls in `archive-agency-phases/docs/phases/evidence-phase23-immune.json`) requires a local model host.
