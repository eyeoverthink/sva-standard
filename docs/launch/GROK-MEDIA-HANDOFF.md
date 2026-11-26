# Grok / OhGee Media Co-Creation Handoff (`sva-standard@v1.6.0`)

Paste any section below directly into **Grok** or your **Grok bot (`OhGee`)** to generate thumbnails, diagram stills for `fraymus-video-studio`, or short-form social cuts — with strict factual guardrails baked in so every asset stays 100% accurate and zero-hype.

---

## Master Context Block (Always Paste at the Top of Your Grok Prompt)

```text
You are helping produce launch media for `eyeoverthink/sva-standard` (v1.6.0, Apache-2.0).

HARD ACCURACY & STYLE RULES (DO NOT VIOLATE):
1. ZERO sci-fi, consciousness, quantum, or metaphysical buzzwords (NO glowing AI brains, NO neon robots, NO "AGI", NO "unbreakable", NO "quantum", NO "consciousness", NO "phi^75").
2. Visual aesthetic: crisp dark-mode engineering schematic / terminal / cryptography blueprint (#0B0B0F charcoal background, #00F3FF cyan + #00FF66 emerald pass badges + #FF4466 red fail/block badges, clean monospace typography, high contrast, minimal clutter).
3. Only cite these exact verified facts:
   - Live offline browser labs (0 backend, 0 external CDNs): https://eyeoverthink.github.io/sva-standard/
   - GitHub repo: https://github.com/eyeoverthink/sva-standard
   - 96/96 golden conformance vectors passing identically across 3 zero-dep runtimes: Node.js V8, Browser W3C WebCrypto, and Single-File Pure Java 25 (with built-in pure-Java WASM VM).
   - Format-agnostic OPEG/1 execution gate (refuses DIRECT_INFERENCE until a receipt verifies) working with BOTH SVA-ER/1 (Ed25519 + RFC 6962 Merkle) AND real served IETF draft-zambo-aer1-26 (AER-1 v0.4) receipts (2 merged interop PRs with @zambodotdev).
   - @eyeoverthink/privacy-membrane@1.3.0 (12.7 kB, 0 deps): StreamSealGuard catches split-token API keys ("sk-" + "ant-...") and digit-squeezed SSNs before egress.
   - Honest limits: proves integrity/completeness of what the host recorded, not that a compromised host didn't lie before signing; deterministic verification covers math/code/WASM, not subjective prose.
```

---

## Prompt A — YouTube 16:9 Thumbnail + 9:16 Shorts Cover (Image Generation)

```text
Using the Master Context Block above, generate a crisp, minimalist 16:9 YouTube thumbnail (and a 9:16 vertical variant) for a developer video titled "Verifiable AI Agents — Offline in 10 Seconds".

Layout:
- Dark charcoal blueprint background (#0B0B0F) with subtle 1px engineering grid lines.
- Left side: stark red terminal badge reading "DIRECT_INFERENCE: BLOCKED" with a small broken-link icon.
- Right side: crisp emerald terminal badge reading "S4_COMMIT: VERIFIED (96/96)" with subtle Ed25519 + Merkle tree line diagram.
- Top-right small monospace pill: "0 BACKEND · 0 DEPS · APACHE-2.0".
- Clean, legible geometric sans/monospace typography, high contrast at small mobile sizes, NO faces, NO glowing sci-fi brains, NO stock cyberpunk tropes.
```

---

## Prompt B — 3 Diagram Stills for `fraymus-video-studio` (`visuals: local`)

```text
Using the Master Context Block above, generate 3 clean 1920x1080 dark-mode architecture diagram PNGs (matching #0B0B0F background, cyan #00F3FF, emerald #00FF66, red #FF4466) that I will drop directly into fraymus-video-studio scenes:

1. `scene_opeg_gate.png`: Clean horizontal flowchart: S0 Goal -> S1 Plan -> S2 Execute & HALT -> S3 Sanitize (R_san) -> [Receipt Gate: SVA-ER/1 or IETF AER-1] -> S4 Commit (green check), with a red blocked branch labeled "DIRECT_INFERENCE -> REJECTED".
2. `scene_tri_runtime.png`: One central JSON box labeled "96 Golden Vectors" branching cleanly into 3 green-checked runtime boxes: "Node.js V8 (~28 ms)", "Browser WebCrypto (~52 ms, 0 node:crypto)", and "Single-File Java 25 + Pure-Java WASM VM (~270 ms)".
3. `scene_stream_guard.png`: Token-stream diagram showing Chunk 1: `"Using key sk-"` (held in boundary buffer) + Chunk 2: `"ant-api03-..."` -> StreamSealGuard -> Output: `"Using key [SECRET_1]"` with a green badge `audit.clean = true · 0 leaks`.
```

---

## Prompt C — Render Directly with `fraymus-video-studio` (Local, $0)

Once you have `sva-explainer.md` (and optional Grok PNGs wired via `visual: path/to/scene.png` if desired):

```bash
# 16:9 YouTube 1080p master + 720p phone copy (fully procedural, 0 GPU, $0):
studio render f:\eyeoverthink-sva\sva-standard\docs\launch\sva-explainer.md

# 9:16 vertical cut for YouTube Shorts / Reels / X:
studio render f:\eyeoverthink-sva\sva-standard\docs\launch\sva-explainer.md --format 9:16
```
