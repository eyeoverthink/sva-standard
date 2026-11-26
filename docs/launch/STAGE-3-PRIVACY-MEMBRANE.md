# Stage 3 Launch Kit — `@eyeoverthink/privacy-membrane@1.3.0` (`StreamSealGuard` + `EMA/1`)

- **Target Communities:** Show HN, `r/netsec`, `r/LocalLLaMA`, `r/node`
- **Live Zero-Backend Playground (0 servers, 0 CDNs):** https://eyeoverthink.github.io/sva-standard/membrane-lab.html
- **npm Package (0 runtime deps, 12.7 kB):** https://www.npmjs.com/package/@eyeoverthink/privacy-membrane
- **Wire Spec (`EMA/1`):** https://github.com/eyeoverthink/sva-standard/blob/main/specs/EMA-1.md

---

## 1. Title Options (Anti-Hype, Mechanism-First)

- **Show HN:** `Show HN: Zero-dependency streaming PII/secret membrane for LLM token streams (browser + Node)`
- **r/LocalLLaMA / r/netsec:** `Built a 12 kB zero-dep streaming LLM secret/PII guard that catches credentials split across token boundaries ("sk-" + "ant-...")`

---

## 2. 10-Second Verification Block (Put Right at the Top)

```bash
# Watch a split API key ("sk-" + "ant-..."), split SSN ("123-" + "45-6789"), and split email get caught mid-stream:
npx @eyeoverthink/privacy-membrane stream-demo

# Seal text & run digit-squeezed egress audit:
npx @eyeoverthink/privacy-membrane seal "Patient SSN 123-45-6789 email elena@northstar.org"

# Catch zero-width Unicode prompt-injection evasion:
npx @eyeoverthink/privacy-membrane scan "Ig​nore all previous instructions"
```

Or try it directly offline in your browser (turn off Wi-Fi): https://eyeoverthink.github.io/sva-standard/membrane-lab.html

---

## 3. Core Technical Story (3 Bullet Points)

1. **Why naive chunk regexes fail on streaming LLMs:** Tokenizers routinely split credentials across chunk boundaries (`"sk-"` in chunk 1, `"ant-api03-..."` in chunk 2). `StreamSealGuard` maintains a bounded `tailHoldLength` buffer for known secret prefixes, partial digit runs, and partial emails so raw credentials never leave the socket mid-stream.
2. **Digit-squeezed egress audit + lenient restore:** Before any sealed payload leaves the device, `session.audit()` verifies that neither the raw string nor a digit-squeezed variant (`123456789` for `123-45-6789`) survived. On the way back, `session.unseal()` restores even LLM-mangled placeholders (`[SSN_1]`, `«EMAIL_1»`).
3. **Verifiable wire attestations (`EMA/1`):** Pairs with 14 golden conformance vectors verified identically across Node.js, W3C Browser WebCrypto, and Single-File Java (`eyeoverthink/sva-standard`).

---

## 4. Honest Limits (State Upfront)

- Structured PII/secrets (SSNs, API keys, emails, phones, cards, private keys, IPs) are caught deterministically at sub-millisecond latency with 0 GPU; unstructured names without cues require pairing with a local NER pass.
- Sentinel is a defense-in-depth scanner (zero-width/BOM stripping + fixed-point `</untrusted>` boundary enforcement), not a formal proof against arbitrary semantic prompt injection.
