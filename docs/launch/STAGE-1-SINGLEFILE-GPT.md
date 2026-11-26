# Stage 1 Launch Kit — `SingleFileGPT.java` (Weeks 1–2)

> **Launch Guardrails Verified:** Zero bio/sci-fi lore · `<10s` 0-GPU single-command verification · 100% Apache-2.0 local-first · Explicit honest limits & exact hardware (`AMD Ryzen 9 3900X`, JDK 25, 0 dependencies).

---

## T-24h Pre-Flight Checklist
- [x] Clean git tag `v1.0.0` on standalone repo: https://github.com/eyeoverthink/singlefile-gpt
- [x] Run `java SingleFileGPT.java selftest` on a clean checkout — verified **79/79 passed in 7.63 s**.
- [ ] Run `java SingleFileGPT.java bench dim=512 heads=8 layers=8 ctx=128 len=60 sweep=1,2,3,4,6,8` and record terminal clip.

---

## T+0h — 90-Second Own-Voice YouTube Demo Script

- **0:00–0:15 (Hook + Live Command):** "Here's a full decoder-only transformer — GPT-2 BPE tokenizer, RoPE, RMSNorm, SwiGLU, hand-derived backprop, AdamW, int8 and ternary QAT, and a multi-threaded byte-resident inference engine — in one pure Java file with zero dependencies. Watch `java SingleFileGPT.java selftest`." *(Screen: terminal runs `selftest`, green finite-difference gradient checks + bit-identical threaded inference checks finish in seconds.)*
- **0:15–0:40 (Receipts, Not Claims):** "Every op's backward pass is checked against central finite differences. The GPT-2 pretokenizer is checked against `java.util.regex` across all 1.1 million Unicode scalar values. On 1.1 MB of Shakespeare held-out text: `fp64` hits 49.49 perplexity, `int8` row-scale hits 49.56 at 7.4x less memory, post-training ternary collapses to 158.29, and ternary QAT recovers to 50.77."
- **0:40–1:10 (What Failed + Open Challenge):** "Now for the honest part. On my Ryzen 9 3900X at 25.4M params, row-scale `int8` hits 321.9 tok/s at 8 threads — about 5x faster than `double`. We tested Java's incubator Vector API and got 2x more FLOP/s, then rejected it on purpose to stay zero-flag. And look at `T=4`: `int8 g64` drops from 154.4 tok/s at 2 threads down to 135.0 at 4 threads before jumping to 176.0 at 8. We ruled out slice alignment, affinity, and barrier cost — and we still don't know why."
- **1:10–1:30 (CTA):** "Run `bench` on your CPU, tell me if you see the `T=4` dip, and if you isolate the hardware counter or JIT cause with a zero-flag Java fix, I'll merge it within 48 hours."

---

## T+0h — Show HN Submission

**Title:** `Show HN: SingleFileGPT.java – A 0-dep transformer (BPE, QAT, byte-resident) in one Java file`

**Immediate First Comment (Post within 60 seconds):**
> Hi HN — I wrote `SingleFileGPT.java`, a single-file, zero-dependency pure-Java decoder-only transformer (`RMSNorm`/`LayerNorm`, `SwiGLU`/`GELU`, `RoPE`, hand-derived backprop, `AdamW` with bit-exact checkpoint resume, GPT-2 UTF-8 BPE, weight-only `int8` & BitNet-style ternary QAT, byte-resident inference, and a spin-wait thread pool).
>
> **Verify in <10 seconds (0 GPU, no Maven/Gradle, JDK 17+):**
> ```
> java SingleFileGPT.java selftest
> java SingleFileGPT.java bench dim=512 heads=8 layers=8 ctx=128 len=60 sweep=1,2,3,4,6,8
> ```
>
> **Hardware & Real Numbers (AMD Ryzen 9 3900X, JDK 25):**
> - Shakespeare 1.1 MB (90/10 held-out, 49,418 unseen tokens, dim=128, 4L): `fp64` PPL **49.49** (7.4 MB) · `int8` row-scale **49.56** (1.0 MB) · PTQ ternary **158.29** · ternary QAT **50.77** (1.0 MB).
> - Inference speed (dim=512, 8L, 25.4M params, random weights): `double` 51.7 tok/s (T=1) → 75.5 (T=8); `int8` row-scale **237.4 tok/s (T=1) → 321.9 tok/s (T=8)** (bit-identical to single-threaded).
>
> **Honest Limits & What Failed:**
> 1. **No Vector API SIMD by design:** `jdk.incubator.vector` measured 2x faster (12.4 vs 6.0 GFLOP/s) and was intentionally rejected to keep zero flags / zero incubator dependencies.
> 2. **Multiply-free ternary lookup kernel failed:** Ran at ~30 tok/s (4x slower than the plain multiply kernel), so ternary saves RAM here but is not faster than `int8`.
> 3. **Emulated low-precision training:** `precision=fp16|bf16|ternary` rounds weights per step in `double` arithmetic — validates math, not GPU Tensor Core speed.
> 4. **Open puzzle (the `T=4` dip):** On Ryzen 9 3900X, `int8 g64` drops from 154.4 tok/s (`T=2`) to 135.0 (`T=4`) before climbing to 176.0 (`T=8`). We ruled out alignment (`-Dfray.align=8`), affinity masks, and barrier cost (`0.25–1.3 µs`). Curious what other CPUs (Apple Silicon, Intel, Zen 4/5) report!

---

## T+4h — 5-Post X Receipts Thread

1. **Post 1 (Hook + Chart):** Built a complete decoder-only transformer in ONE zero-dependency `.java` file: hand-derived backprop, GPT-2 BPE, AdamW bit-exact resume, int8 + ternary QAT, and byte-resident threaded inference. Run `java SingleFileGPT.java selftest` in <10s, 0 GPU. *[Attach Shakespeare PPL + Ryzen 3900X tok/s chart]*
2. **Post 2 (Terminal Clip):** Every backward op is verified against central finite differences, the GPT-2 pretokenizer is checked against all 1,112,064 Unicode code points, and multi-threaded inference is proven bit-identical to single-threaded across double, int8, and ternary. *[Attach 15s terminal clip of `selftest`]*
3. **Post 3 (Honest Numbers):** Real held-out Shakespeare (49,418 unseen tokens): `fp64` PPL 49.49 (7.4 MB) → `int8` row-scale 49.56 (1.0 MB, lossless) → post-training ternary 158.29 (collapsed) → ternary QAT 50.77 (within 2.6% at 7.4x less RAM).
4. **Post 4 (Failure We Measured & Rejected):** We tried a multiply-free ternary lookup kernel: 30 tok/s (4x slower — killed). We tried Java's incubator Vector API: 2x faster (12.4 vs 6.0 GFLOP/s) — rejected on purpose so `java SingleFileGPT.java` stays zero-flag.
5. **Post 5 (Open Challenge):** Open puzzle on Ryzen 9 3900X (25.4M params): `int8 g64` goes 118.2 (T=1) → 154.4 (T=2) → **135.0 (T=4)** → 176.0 (T=8). Alignment, affinity, and barrier cost (`<1.3 µs`) are ruled out. Run `bench` on your box and reply with your sweep!

---

## T+24h — Native Markdown Post (`r/programming` / `r/LocalLLaMA`)

**Title:** `I wrote a zero-dependency decoder-only transformer (BPE, QAT, byte-resident inference) in a single pure Java file — and hit a weird T=4 Ryzen scaling dip`

*(Lead with the full tables from `singlefile-gpt/README.md`: the 10-second `selftest` + `bench` commands, the Shakespeare 90/10 held-out perplexity table, the Ryzen 9 3900X thread-sweep table, the 3 rejected experiments — Vector API, LUT ternary, dynamic chunk scheduler — and ask the community for `perf stat` / L3 CCX diagnoses on the T=4 dip. Apache-2.0, zero external links required to read the full technical write-up.)*

---

## T+72h — 60-Second YouTube Short Template
- Show the #1 community critique or CPU sweep finding from HN/Reddit, show the exact diff & new `selftest` regression check merged within 48 hours, and run `java SingleFileGPT.java selftest` live on screen.
