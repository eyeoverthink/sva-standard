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
say: Right now, when an AI agent says it ran the math or kept your data private, you mostly have to take its word for it.
# DON'T TRUST THE LOG | VERIFY THE RECEIPT
at: verify

## title
kind: title
# SOVEREIGN VERIFIED | AGENCY (SVA v1.6)
sub: ZERO DEPENDENCIES · OFFLINE PLAYGROUNDS · APACHE-2.0
say: Meet SVA: six zero-dependency open wire standards you can verify offline in under ten seconds.

## split
kind: split
# DIRECT INFERENCE VS. VERIFIED EXECUTION
left: Unverified Agent
right: OPEG/1 Execution Gate
say: A standard agent guesses from weights and leaks split API keys mid-stream. With OPEG-1, direct inference is blocked until a real runtime receipt verifies.
- x Guesses answers from weights @guesses
- x Leaks split keys across tokens @leaks
- + Blocks direct inference at S2 @blocked
- + Unlocks only on verified receipt @receipt

## stat
kind: stat
stat: 96
suffix: /96
# GOLDEN VECTORS | THREE RUNTIMES
say: Ninety-six deterministic golden vectors pass bit-for-bit identically across Node V8, Browser WebCrypto, and a single-file pure Java runner with its own WebAssembly VM.
at: ninety-six

## interop
kind: bullets
# BUILT TO INTEROPERATE | NOT LOCK YOU IN
say: SVA-ER-1 and IETF draft AER-1 now run side-by-side through the same OPEG-1 gate, backed by two merged cross-format pull requests and a streaming split-token privacy membrane.
- + Two merged PRs with IETF draft AER-1 @merged
- + StreamSealGuard catches split sk- keys @stream
- + Live browser labs with zero backend @labs
- + Zero GPU and zero npm runtime deps @zero

## close
kind: end
say: Turn off your Wi-Fi, open eyeoverthink.github.io/sva-standard, and try to break the labs yourself.
# TRY TO BREAK IT OFFLINE | eyeoverthink.github.io/sva-standard
at: break
