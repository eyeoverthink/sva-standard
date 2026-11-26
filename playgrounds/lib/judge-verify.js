// Zero-dependency SVA-JEV/1 Calibrated Epistemic Judge verifier (browser & Node ES module).
// Implements the exact deterministic rules of specs/SVA-JEV-1.md & eyeoverthink/logic-chain-judge.

export const JEV_SEMANTICS = 'stability-signal-not-correctness';
export const JEV_CHOICES = new Set(['decide', 'noise', 'settled']);
export const MIN_CALIBRATION_SAMPLES = 30;
export const CALIBRATION_BASELINE = 2 / 3;
export const MIN_RECALL = 0.9;
export const VOTE_THRESHOLD = 0.8;
export const MIN_INDEPENDENT_VOTERS = 2;
export const MIN_QUOTE_CHARS = 12;

export function wilsonLower95(right, total, z = 1.96) {
  if (!Number.isSafeInteger(total) || total < 1 || !Number.isSafeInteger(right) || right < 0 || right > total) {
    return 0;
  }
  const p = right / total;
  const denom = 1 + (z * z) / total;
  const center = (p + (z * z) / (2 * total)) / denom;
  const margin = (z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total))) / denom;
  return Math.max(0, center - margin);
}

export function flatText(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/[*_`#>]/g, '')
    .replace(/\u2019/g, "'")
    .replace(/[\u201c\u201d]/g, '"')
    .replace(/[\u2013\u2014]/g, '-')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

export function extractFactualTerms(text) {
  const out = new Set();
  if (typeof text !== 'string') return out;
  for (const m of text.matchAll(/\b\d+(?:\.\d+)*\b/g)) {
    const tok = m[0];
    if (tok.length >= 2 || tok.includes('.')) out.add(tok.toLowerCase());
  }
  for (const m of text.matchAll(/\b(?:[A-Za-z]+_[A-Za-z0-9_]+|[a-z]+[A-Z][A-Za-z0-9]*)\b/g)) {
    out.add(m[0].toLowerCase());
  }
  return out;
}

export function evaluateSvaJev1(doc) {
  const fail = (reason, extra = {}) => ({ ok: false, mode: doc?.mode ?? 'unknown', reason, ...extra });
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return fail('not an object');
  if (doc.spec !== 'sva-jev/1') return fail('invalid spec (expected sva-jev/1)');
  if (doc.semantics !== JEV_SEMANTICS) return fail('missing required semantics: stability-signal-not-correctness');

  if (doc.mode === 'calibration') {
    const { answered, total, right, realFound, realTotal } = doc;
    if (![answered, total, right, realFound, realTotal].every((n) => Number.isSafeInteger(n))) {
      return fail('non-integer calibration counts');
    }
    if (total < 1 || answered < 0 || answered > total || right < 0 || right > answered) {
      return fail('invalid answered/total/right bounds');
    }
    if (realTotal < 1 || realFound < 0 || realFound > realTotal) {
      return fail('invalid realFound/realTotal bounds');
    }
    const low = wilsonLower95(right, total);
    const found = realFound / realTotal;
    const accuracy = right / total;
    const standing = (answered >= MIN_CALIBRATION_SAMPLES && low > CALIBRATION_BASELINE && found >= MIN_RECALL)
      ? 'calibrated'
      : 'uncalibrated';
    if (standing !== 'calibrated') {
      return fail('candidate failed Wilson-CI/recall calibration gate', {
        standing, accuracy: Number(accuracy.toFixed(4)), wilsonLow95: Number(low.toFixed(4)), found: Number(found.toFixed(4)),
      });
    }
    return {
      ok: true, mode: 'calibration', standing,
      accuracy: Number(accuracy.toFixed(4)), wilsonLow95: Number(low.toFixed(4)), found: Number(found.toFixed(4)),
    };
  }

  if (doc.mode === 'vote') {
    const { author, ballots, declaredDecision } = doc;
    if (typeof author !== 'string' || !author.length) return fail('missing author identity');
    if (!ballots || typeof ballots !== 'object' || Array.isArray(ballots)) return fail('missing ballots map');
    if (declaredDecision !== 'settled' && declaredDecision !== 'escalate_human') {
      return fail('declaredDecision must be settled or escalate_human');
    }
    let excludedAuthor = false;
    let clearCount = 0;
    let humanCount = 0;
    let validCount = 0;
    for (const [voter, choice] of Object.entries(ballots)) {
      if (voter === author) { excludedAuthor = true; continue; }
      if (!JEV_CHOICES.has(choice)) continue;
      validCount++;
      if (choice === 'decide') humanCount++;
      else clearCount++;
    }
    const computedDecision = (validCount >= MIN_INDEPENDENT_VOTERS && (clearCount / validCount) >= VOTE_THRESHOLD)
      ? 'settled'
      : 'escalate_human';
    if (declaredDecision !== computedDecision) {
      return fail(`declaredDecision=${declaredDecision} violates JEV rule (computed=${computedDecision})`, {
        excludedAuthor, validCount, clearCount, humanCount, computedDecision,
      });
    }
    return {
      ok: true, mode: 'vote', excludedAuthor, validCount, clearCount, humanCount, computedDecision,
      semantics: JEV_SEMANTICS,
    };
  }

  if (doc.mode === 'quote_check') {
    const { document, verdicts, declaredMetCount } = doc;
    if (typeof document !== 'string' || !Array.isArray(verdicts) || verdicts.length === 0) {
      return fail('missing document or verdicts array');
    }
    if (!Number.isSafeInteger(declaredMetCount) || declaredMetCount < 0) return fail('invalid declaredMetCount');
    const plain = flatText(document);
    let acceptedMet = 0;
    let rejectedQuotes = 0;
    const rejectedIds = [];
    for (const v of verdicts) {
      if (!v || typeof v !== 'object' || typeof v.id !== 'string' || !v.id.length || typeof v.met !== 'boolean') {
        return fail('malformed verdict entry');
      }
      if (v.met) {
        const q = flatText(v.quote);
        if (q.length >= MIN_QUOTE_CHARS && plain.includes(q)) {
          acceptedMet++;
        } else {
          rejectedQuotes++;
          rejectedIds.push(v.id);
        }
      }
    }
    if (rejectedQuotes > 0) {
      return fail('unverified or short quote rejected mechanically', { acceptedMet, rejectedQuotes, rejectedIds });
    }
    if (acceptedMet !== declaredMetCount) {
      return fail(`declaredMetCount=${declaredMetCount} != acceptedMet=${acceptedMet}`, { acceptedMet, rejectedQuotes });
    }
    return { ok: true, mode: 'quote_check', acceptedMet, rejectedQuotes: 0, totalItems: verdicts.length };
  }

  if (doc.mode === 'claim_trace') {
    const { ledgerTexts, briefText, plantedFakes, allowNewTerms = false } = doc;
    if (!Array.isArray(ledgerTexts) || ledgerTexts.length === 0 || !ledgerTexts.every((s) => typeof s === 'string')) {
      return fail('missing ledgerTexts array');
    }
    if (typeof briefText !== 'string') return fail('missing briefText');
    if (!Array.isArray(plantedFakes) || plantedFakes.length === 0) return fail('missing plantedFakes control array');
    let falseSupported = 0;
    const missedFakeIds = [];
    for (const f of plantedFakes) {
      if (!f || typeof f !== 'object' || typeof f.id !== 'string' || !['supported', 'unsupported', 'contradicted'].includes(f.verdict)) {
        return fail('malformed plantedFake entry');
      }
      if (f.verdict === 'supported') {
        falseSupported++;
        missedFakeIds.push(f.id);
      }
    }
    const ledgerTerms = new Set();
    for (const t of ledgerTexts) {
      for (const tok of extractFactualTerms(t)) ledgerTerms.add(tok);
    }
    const briefTerms = extractFactualTerms(briefText);
    const newTerms = [...briefTerms].filter((tok) => !ledgerTerms.has(tok)).sort();

    if (falseSupported > 0) {
      return fail('judge marked planted fake claim as supported', {
        plantedTotal: plantedFakes.length, falseSupported, missedFakeIds, newTerms,
      });
    }
    if (!allowNewTerms && newTerms.length > 0) {
      return fail('deterministic new_terms scanner found invented terms absent from ledger', {
        plantedTotal: plantedFakes.length, falseSupported: 0, newTerms,
      });
    }
    return {
      ok: true, mode: 'claim_trace',
      plantedTotal: plantedFakes.length, plantedCaught: plantedFakes.length, falseSupported: 0, newTerms,
    };
  }

  return fail(`unsupported mode: ${doc.mode}`);
}
