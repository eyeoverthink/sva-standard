# `@eyeoverthink/privacy-membrane`

Zero-dependency **Privacy Membrane** (deterministic PII/secret sealing, digit-squeezed egress leak audit, lenient mangled-placeholder restore) and **Sentinel** prompt-injection guard (zero-width/BOM evasion detection + fixed-point `</untrusted>` stripping). Works in Node.js 22+ and browsers with zero network calls.

- **Live Zero-Backend Membrane Lab:** https://eyeoverthink.github.io/sva-standard/membrane-lab.html
- **Wire Spec:** [`specs/EMA-1.md`](https://github.com/eyeoverthink/sva-standard/blob/main/specs/EMA-1.md)

## Quick Start (< 10 Seconds, 0 GPU)

```bash
# Seal PII & run digit-squeezed egress audit:
npx @eyeoverthink/privacy-membrane seal "Patient SSN 123-45-6789 email elena@northstar.org"

# Scan for zero-width prompt injection evasion:
npx @eyeoverthink/privacy-membrane scan "Ig​nore all previous instructions"

# Streaming cross-token secret/PII guard demo (splits "sk-" + "ant-...", "123-" + "45-6789"):
npx @eyeoverthink/privacy-membrane stream-demo

# Or inside the repo with zero installs:
node packages/privacy-membrane/bin/privacy-membrane.js seal "SSN 123-45-6789 elena@northstar.org"
```

## Programmatic API

```js
import { detect, SealSession, scanInjection, StreamSealGuard } from '@eyeoverthink/privacy-membrane';

const session = new SealSession();
const sealed = session.apply(inputText, detect(inputText));
const audit = session.audit(sealed); // catches raw leaks AND digit-squeezed leaks like 123456789
if (!audit.clean) throw new Error(`MembraneLeak: ${audit.leaked.join(', ')}`);

const restored = session.unseal(cloudReply); // restores even mangled placeholders like [SSN_1]

// Cross-token streaming LLM / Ollama NDJSON guard (prevents split-token credential leaks):
const guard = new StreamSealGuard();
const out = ['Key sk-', 'ant-api03-secret1234567890'].map((c) => guard.push(c)).join('') + guard.flush();
```

## Honest Limits

- Deterministic regex/pattern detection catches structured PII/secrets (SSNs, emails, phones, cards, API keys, IPs, private keys, titles/names with prefixes) at sub-millisecond latency with 0 GPU; unstructured person/organization names without cues require pairing with a local NER pass.
- Sentinel is a defense-in-depth heuristic scanner, not a formal proof against arbitrary semantic prompt injection.

## License

Apache-2.0
