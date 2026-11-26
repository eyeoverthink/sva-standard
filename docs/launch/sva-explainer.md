---
title: Verifiable AI Agents Without the Hype
recipe: explainer
byline: eyeoverthink/sva-standard · Apache-2.0
voice: piper:en_US-ryan-high
theme: teal
music: pad
visuals: procedural
format: 16:9
---
## hook
kind: statement
say: Right now, when an AI agent says it ran the math, kept your data private, or checked its own plan, you mostly have to take its word for it.
# DON'T TRUST THE LOG | VERIFY THE RECEIPT
at: verify

## title
kind: title
# SOVEREIGN VERIFIED | AGENCY (SVA v1.7)
sub: 7 SPECS · 5 OFFLINE PLAYGROUNDS · 0 DEPENDENCIES · APACHE-2.0
say: Meet SVA: seven zero-dependency open wire standards spanning execution proofs, boundary gates, and a calibrated epistemic judge you can test offline in ten seconds.

## split
kind: split
# DIRECT INFERENCE VS. VERIFIED EXECUTION
left: Unverified Agent
right: OPEG/1 + SVA-JEV/1
say: A standard agent guesses from weights, leaks split API keys mid-stream, and grades its own work. With OPEG-1 and SVA-JEV-1, direct inference is blocked and unquoted or fake judge claims are rejected automatically.
- x Guesses answers from weights @guesses
- x Leaks split keys across tokens @leaks
- + Blocks direct inference at S2 @blocked
- + Rejects unquoted & fake judge claims @judge

## stat
kind: stat
stat: 106
suffix: /106
# GOLDEN VECTORS | THREE RUNTIMES
say: One hundred and six deterministic golden vectors pass bit-for-bit identically across Node V8, Browser WebCrypto, and a single-file pure Java runner with its own WebAssembly VM.
at: one hundred

## judge
kind: bullets
# LAYER 3: THE CALIBRATED JUDGE | SVA-JEV/1
say: For open-ended prose and plans, logic-chain-judge requires Wilson confidence calibration, excludes author self-votes, enforces verbatim quotes, and hides planted fakes that caught thirty-two out of thirty-two fabricated claims.
- + Wilson 95% CI > 2/3 panel calibration @wilson
- + 32/32 planted fakes caught (0 supported) @fakes
- + Halo disagreement cut 12/30 to 4/30 @halo
- + Replay-verified Ed25519 -> SVA-ER/1 export @replay

## interop
kind: bullets
# BUILT TO INTEROPERATE | NOT LOCK YOU IN
say: SVA-ER-1 and IETF draft AER-1 run side-by-side through the same OPEG-1 gate, backed by two merged cross-format pull requests and a streaming split-token privacy membrane.
- + Two merged PRs with IETF draft AER-1 @merged
- + StreamSealGuard catches split sk- keys @stream
- + Five live browser labs with zero backend @labs
- + Zero GPU and zero npm runtime deps @zero

## close
kind: end
say: Turn off your Wi-Fi, open eyeoverthink.github.io/sva-standard, and try to break all five labs yourself.
# TRY TO BREAK IT OFFLINE | eyeoverthink.github.io/sva-standard
at: break
