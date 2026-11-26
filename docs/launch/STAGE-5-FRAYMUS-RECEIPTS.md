# Stage 5 Launch Kit — `eyeoverthink/fraymus-receipts` (`v1.0.0`)

- **Target Communities:** Hacker News, `r/MachineLearning`, `r/compsci`, `r/WebAssembly`
- **Repo & Release:** https://github.com/eyeoverthink/fraymus-receipts
- **License:** Apache-2.0

---

## 1. Title Options (Radical Honesty Wins HN)

- **Show HN:** `Show HN: Receipts over testimony – We benchmarked 6 of our own claims; 4 held, 1 partially held, 1 failed`
- **r/WebAssembly / r/compsci:** `Formal WASM custom-section binary container spec (FRYM v1) + 6 runnable benchmarks reporting both wins and failed claims`

---

## 2. 10-Second Verification Block

```bash
git clone https://github.com/eyeoverthink/fraymus-receipts && cd fraymus-receipts
pip install -r requirements.txt
python -m pytest tests -q          # 51 tests incl. Wasmtime module load checks
python bench/bench_contour.py      # Reproduces both the +14.4% clean-curve loss AND the -25%..-42% noisy-curve win
python bench/bench_rip.py          # 100% recall at 90% erasure vs 0% hash baseline; fails >50% bit flips
```

---

## 3. Why Readers Will Actually Trust This Repo

Every claim is tested against a fair baseline, and **failures are published in the exact same table as wins** (`docs/RESULTS.md`):

| Claim | Measured Verdict |
|---|---|
| File → loadable WASM custom-section module → byte-exact recovery | **Verified** (~2.5 KB fixed envelope, attacker-bounded lengths, loads in Wasmtime) |
| 16,384-bit Q64 fixed-point hypervector | **Verified** for substitution (`0.9982` on 1B edit), **fails** 1-byte insertion (`0.5589`) |
| Goertzel resonance recognition < 1 ms | **Verified** (`0.085 ms p50`, 93.8% recall, 0% false accepts at 64 kHz; speed is vectorization) |
| Contour simplification 37% more accurate than RDP | **Not reproduced** (`+14.4%` worse overall; **−25% to −42%** better only when denoising noisy curves at σ ≥ 0.03) |
| Distributed memory survives 80% store corruption | **Verified for erasure** (`100%` recall at 90% erased vs `0%` hash table), **fails** >50% bit flips |
| Mesh trust score `E(t)` | **Verified** only after fixing 2 contradictions in the original prose spec |

Plus [docs/SPEC-fraymus-custom-section.md](https://github.com/eyeoverthink/fraymus-receipts/blob/main/docs/SPEC-fraymus-custom-section.md) includes an explicit **"What this is not"** section (not compression, not encryption, not a safe filename, not a signature).
