# `@eyeoverthink/skill-crystallizer`

Zero-dependency, **zero-LLM** skill binder induction with leave-one-out cross-validation and positional wording gates. Induces deterministic argument extractors from positive + negative examples, routes matching fresh prompts in `< 1 ms` at **0 LLM calls**, and refuses near-miss traps (sales tax, tips, extra quantities).

- **Live Zero-Backend Skill Lab:** https://eyeoverthink.github.io/sva-standard/skill-lab.html

## Quick Start (< 10 Seconds, 0 GPU)

```bash
# Valid fresh task -> routed in <1 ms at 0 LLM calls (answer: 162):
npx @eyeoverthink/skill-crystallizer "A \$240 coat is 25% off, then an extra 10% off. What is the final price?"

# Near-miss sales-tax trap -> safely refused (routed: false):
npx @eyeoverthink/skill-crystallizer "A \$200 laptop is 20% off, then 8% sales tax is added. What is the final price?"

# Or inside the repo with zero installs:
node packages/skill-crystallizer/bin/skill-crystallizer.js
```

## Programmatic API

```js
import { induce, leaveOneOut, applySpec, novelWording } from '@eyeoverthink/skill-crystallizer';

const { spec } = induce(positiveExamples, negativeExamples, skillSchema);
const cv = leaveOneOut(positiveExamples, negativeExamples, skillSchema);
const bound = applySpec(spec, freshTask);
const novel = novelWording(positiveExamples, freshTask);
const safeToRoute = Boolean(bound && novel.length === 0);
```

## Honest Limits

- Proven on structured numeric/parameterized tasks where arguments appear explicitly as numbers/units in the prompt; open-ended prose synthesis and multi-hop symbolic algebra remain outside scope and should fall through to a verified agent loop.
- Deliberately conservative: unseen wording near numeric slots triggers a safe refusal (`novelWording.length > 0`) rather than risking silent misrouting.

## License

Apache-2.0
