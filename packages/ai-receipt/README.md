# `@eyeoverthink/ai-receipt`

Zero-dependency offline **AI Execution Receipt (`AER/1`)** verifier using standard RFC primitives (`Ed25519` RFC 8032, `SHA-256`, `RFC 6962` `0x00`/`0x01` Merkle proofs with odd-node promotion, `RFC 8785` JCS). Works identically in Node.js 22+ and modern browsers via W3C WebCrypto.

- **Live Zero-Backend Tamper Lab:** https://eyeoverthink.github.io/sva-standard/receipt-lab.html
- **Wire Spec:** [`specs/AER-1.md`](https://github.com/eyeoverthink/sva-standard/blob/main/specs/AER-1.md)

## Quick Start (< 10 Seconds, 0 GPU)

```bash
npx @eyeoverthink/ai-receipt verify receipt.json deliverable.txt
# Or directly inside the repo with zero installs:
node packages/ai-receipt/bin/ai-receipt.js verify receipt.json deliverable.txt
```

## Programmatic API

```js
import { verifyReceipt } from '@eyeoverthink/ai-receipt';

const result = await verifyReceipt(receiptJson, { deliverable: deliverableText });
if (!result.ok) {
  console.error(result.checks.filter((c) => !c.ok));
}
```

## What It Catches Offline

- Deliverable modified by even 1 trailing space (`deliverableSha256` mismatch)
- Altered entry content or inflated critic score (entry hash + Ed25519 signature failure)
- Stripped `IN_CLOUD` or blocked-egress entries (`entries.length === statement.entries` completeness check)
- Stripped + duplicated entries to fake count (unique in-range `seq` check)
- Forged Merkle proof or CVE-2012-2459 odd-leaf duplication collision (RFC 6962 `0x00`/`0x01` domain separation + exact depth/parity)
- Swapped agency public key

## Honest Limits

- Proves cryptographic integrity and completeness of what the signing agency recorded; it cannot prevent a compromised host from lying *before* signing an entry.
- Browser WebCrypto `Ed25519` requires Chromium 113+, Firefox 129+, or Safari 17+ over `https://` or `http://localhost`.

## License

Apache-2.0
