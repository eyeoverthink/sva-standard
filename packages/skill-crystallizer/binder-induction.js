// Binder induction: learn how to bind a skill from its own recorded bindings, with no model at all.
//
// Measured in Phase 11: a 7B code model asked to write a regex parser from examples produced parsers that returned
// null on 6-7 of 7 recorded bindings (one was not even valid JavaScript). But the examples themselves already say how
// binding works ("original_price is the number after $, discount1 is the first percentage / 100"). Induction finds,
// for every parameter, ONE selector (number kind x position x scale) consistent with every example, records the
// task "shape" (how many numbers of each kind), and learns question words that only ever appeared in tasks the skill
// must refuse. Leave-one-out: each example must be predicted by the spec induced from all the others.
// The spec compiles to a self-contained `function bind(task)` so it runs, hashes and verifies like any binder.

const KINDS = ['currency', 'percent', 'plain'];
const round = (x) => Math.round(x * 1e9) / 1e9;

/**
 * Numbers in a task, each tagged by kind: "$40" currency, "25%" percent, anything else plain. Each also carries its
 * context: up to 3 content words right after it, within its clause ("5% sales tax is added" -> sales, tax, added).
 */
export function numberTokens(task) {
  const s = String(task), out = [];
  const STOPC = ['and', 'then', 'the', 'that', 'this', 'for', 'with', 'from', 'are', 'was', 'its', 'your'];
  const re = /(\$\s?)?(?<![\w.])(-?\d+(?:\.\d+)?)(\s*%|\s?percent\b)?(?:\s?([a-z]+(?:\/[a-z]+)?))?/gi;
  let m;
  while ((m = re.exec(s))) {
    const end = m.index + (m[1] || '').length + m[2].length + (m[3] || '').length;
    const rest = s.slice(end).split(/[,;:?!]|\.(?!\d)|\d/)[0].toLowerCase();
    const ctx = (rest.match(/[a-z]{3,}/g) || []).filter((w) => !STOPC.includes(w)).slice(0, 3);
    out.push({ v: Number(m[2]), kind: m[1] ? 'currency' : m[3] ? 'percent' : 'plain', unit: !m[1] && !m[3] && m[4] ? m[4].toLowerCase() : null, ctx });
  }
  return out;
}

export const shapeOf = (toks) => KINDS.map((k) => toks.filter((t) => t.kind === k).length).join(',');

/** Content words of the question sentence (the last sentence with a "?", else the last sentence). Self-contained. */
export function questionWords(task) {
  const STOPW = ['the', 'and', 'for', 'with', 'that', 'this', 'what', 'how', 'much', 'many', 'does', 'did', 'was', 'are', 'its', 'their', 'your', 'you', 'now', 'then', 'after', 'from', 'into', 'over', 'whole', 'all'];
  const parts = String(task).split(/(?<=[.!?])\s+/);
  const q = [...parts].reverse().find((x) => x.includes('?')) || parts[parts.length - 1] || '';
  return (q.toLowerCase().match(/[a-z]{3,}/g) || []).filter((w) => !STOPW.includes(w));
}

const declaresDecimal = (p) => /\b(decimal|fraction)\b/i.test(`${p?.description || ''} ${p?.items?.description || ''}`);
const eq = (a, b) => (Array.isArray(a) ? Array.isArray(b) && a.length === b.length && a.every((x, i) => eq(x, b[i])) : typeof a === 'number' && typeof b === 'number' && Math.abs(a - b) <= Math.max(1e-9, Math.abs(a) * 1e-9));

function pick(toks, s) {
  const list = toks.filter((t) => s.kind === 'any' || t.kind === s.kind);
  if (s.all) return list.map((t) => round(t.v * s.scale));
  const t = s.k >= 0 ? list[s.k] : list[list.length + s.k];
  if (t === undefined || (s.units && !s.units.includes(t.unit))) return undefined;
  return round(t.v * s.scale);
}

/** Induce a binding spec from positive examples; null-safe. Returns { spec } or { error }. */
export function induce(pos, neg, skill) {
  if (!pos.length) return { error: 'no positive examples' };
  const props = skill.params?.properties || {};
  const keys = Object.keys(pos[0].input || {}).filter((k) => pos.every((e) => e.input && k in e.input));
  if (!keys.length) return { error: 'examples share no input keys' };
  const toks = pos.map((e) => numberTokens(e.task));
  const shapes = [...new Set(toks.map(shapeOf))];
  if (shapes.length > 2) return { error: `examples have ${shapes.length} different number shapes` };
  const maxN = Math.max(...toks.map((t) => t.length));
  const params = {};
  for (const key of keys) {
    const p = props[key] || {};
    const scales = declaresDecimal(p) ? [0.01, 1] : [1];
    const cands = [];
    for (const kind of [...KINDS, 'any']) for (const scale of scales) {
      if (p.type === 'array' || Array.isArray(pos[0].input[key])) cands.push({ kind, all: true, scale });
      else for (let k = 0; k < maxN; k++) cands.push({ kind, k, scale }, { kind, k: -(k + 1), scale });
    }
    const hit = cands.find((s) => pos.every((e, i) => eq(pick(toks[i], s), e.input[key])));
    if (!hit) return { error: `no single rule finds ${key} in every example` };
    // Plain numbers carry their units: measured, positions alone could not tell "40 mph ... 60 mph" from
    // "120 miles in 2 hours", so the speed binder was (correctly) refused until units were learned.
    if (hit.kind === 'plain' || hit.kind === 'any') {
      const units = toks.map((t) => { const l = t.filter((x) => hit.kind === 'any' || x.kind === hit.kind); return (hit.k >= 0 ? l[hit.k] : l[l.length + hit.k])?.unit; });
      if (units.every(Boolean)) hit.units = [...new Set(units)].sort();
    }
    params[key] = hit;
  }
  return { spec: { shapes, params, ...learnBlocks(pos, neg) } };
}

/**
 * What the skill's refusals teach, independent of any binder: question block words, and body block words after
 * numbers of a "role-marked" kind. Used by induction AND directly by the model binder's gate, so a lesson survives
 * even when the binder that misrouted is retired and its replacement is not (yet) admitted.
 */
export function learnBlocks(pos, neg) {
  // A block word must never occur anywhere in a positive task: measured, a single counter-example otherwise taught
  // the binder to refuse every task containing 'off'.
  const posQ = new Set(pos.flatMap((e) => String(e.task).toLowerCase().match(/[a-z]{3,}/g) || []));
  const blockWords = [...new Set(neg.flatMap((e) => questionWords(e.task)))].filter((w) => !posQ.has(w)).sort();
  // Body block words (Phase 12). Measured in Phase 11: "20% off and then 5% sales tax is added" got past every
  // binder, because the tax is in the body, not the question. The words right after a number name its role ("20% OFF",
  // "5% sales TAX"), but only for number kinds whose role wording REPEATS across good examples (a closed vocabulary:
  // "off" follows a percentage in most discount tasks). After "$90 jacket" comes an item noun that differs in every
  // task (an open vocabulary), so a refused jacket task never teaches the binder to refuse jackets.
  const ctxOf = (task, kind) => numberTokens(task).filter((t) => t.kind === kind).flatMap((t) => t.ctx);
  // With few examples, "half" is a coincidence: measured on the demo rehearsal, 2 of a composed skill's 3 positives said
  // "$… dinner", so "$" looked role-marked and a fresh "$250 birthday dinner" task was refused as unverified wording.
  // A role word must repeat in at least 3 positives (all of them when there are only 2), and in half of a large set.
  const need = Math.max(2, Math.min(pos.length, 3), Math.ceil(pos.length / 2));
  const kinds = KINDS.filter((k) => {
    const n = new Map();
    for (const e of pos) for (const w of new Set(ctxOf(e.task, k))) n.set(w, (n.get(w) || 0) + 1);
    return [...n.values()].some((c) => c >= need);
  });
  const words = [...new Set(neg.flatMap((e) => kinds.flatMap((k) => ctxOf(e.task, k))))].filter((w) => !posQ.has(w)).sort();
  return { blockWords, contextBlock: { kinds, words } };
}

/**
 * A confirmed failure contests the positives that look like it. Measured on the live home: four sales-tax misroutes
 * had been stored as POSITIVE examples (no gate could see them), and because a block word may never occur in a
 * positive task, they made "tax" impossible to learn: the misroute had immunized itself. When the critic rejects a
 * route, the rejected task's RARE role words (after a role-marked number, in under 25% of positives: "tax", not "off")
 * mark every positive that shares them as disputed. If that would contest over a third of the positives, the evidence
 * conflicts too much and nothing is demoted.
 */
export function contested(pos, task) {
  const { kinds } = learnBlocks(pos, []).contextBlock;
  const ctx = (t) => new Set(numberTokens(t).filter((x) => kinds.includes(x.kind)).flatMap((x) => x.ctx));
  const sets = pos.map((e) => ctx(e.task));
  const words = [...ctx(task)].filter((w) => sets.filter((s) => s.has(w)).length < pos.length * 0.25).sort();
  const hit = pos.filter((_, i) => words.some((w) => sets[i].has(w)));
  return hit.length > pos.length / 3 ? { words, examples: [], tooMany: hit.length } : { words, examples: hit };
}

/** The words that say what a task's numbers MEAN: role words after role-marked numbers, plus its question words. */
export function wordingOf(task, kinds) {
  // Role words carry their position: which occurrence of which number kind they follow. Measured in Phase 14: a
  // tax-then-split skill had verified "off" (after the 1st %) and "sales tax added" (after the 2nd), so a discount task
  // ("off" after BOTH) looked fully verified and was routed to it with zero calls. "off" after the 2nd % is new wording.
  // Occurrences are counted in the task's fullest line: mission prompts restate the goal on other lines (Phase 11).
  const SIGN = { percent: '%', currency: '$', plain: 'number' };
  const seen = {};
  const fullest = String(task).split(/\n+/).reduce((a, b) => (numberTokens(b).length > numberTokens(a).length ? b : a), '');
  const roles = numberTokens(fullest).filter((t) => kinds.includes(t.kind)).flatMap((t) => {
    seen[t.kind] = (seen[t.kind] || 0) + 1;
    return t.ctx.map((w) => `${w} after ${SIGN[t.kind]} #${seen[t.kind]}`);
  });
  return [...new Set([...roles, ...questionWords(task)])];
}

/**
 * Wording never seen in a positive example. Measured in Phase 12: every misroute any binder made was recorded as a
 * positive and then shielded itself, so a binding is only trusted when its wording has been verified before. Novel
 * wording ("8% tax", "an 18% tip") is not routed; the agent loop answers it, and the answers are compared.
 */
export function novelWording(pos, task) {
  const { kinds } = learnBlocks(pos, []).contextBlock;
  const known = new Set(pos.flatMap((e) => wordingOf(e.task, kinds)));
  return wordingOf(task, kinds).filter((w) => !known.has(w));
}

/** Apply a spec to a task (the same logic the compiled binder runs). */
export function applySpec(spec, task) {
  const toks = numberTokens(task);
  if (!spec.shapes.includes(shapeOf(toks))) return null;
  const q = questionWords(task);
  if (spec.blockWords.some((w) => q.includes(w))) return null;
  const cb = spec.contextBlock;
  if (cb && toks.some((t) => cb.kinds.includes(t.kind) && t.ctx.some((w) => cb.words.includes(w)))) return null;
  const out = {};
  for (const [k, s] of Object.entries(spec.params)) { const v = pick(toks, s); if (v === undefined) return null; out[k] = v; }
  return out;
}

/** Leave-one-out: every example must be predicted by the spec induced from all the others. */
export function leaveOneOut(pos, neg, skill) {
  return pos.map((e, i) => {
    const rest = pos.filter((_, j) => j !== i);
    const r = induce(rest, neg, skill);
    const got = r.spec ? applySpec(r.spec, e.task) : null;
    const ok = Boolean(got) && Object.keys(e.input).every((k) => eq(got[k], e.input[k]));
    // A miss only because the held-out example has a unit no other example has ("knots") is novelty, not contradiction.
    let novel = false;
    if (!ok && r.spec) {
      const loose = { ...r.spec, params: Object.fromEntries(Object.entries(r.spec.params).map(([k, p]) => [k, { ...p, units: undefined }])) };
      const g2 = applySpec(loose, e.task);
      novel = Boolean(g2) && Object.keys(e.input).every((k) => eq(g2[k], e.input[k]));
    }
    return { task: e.task, ok, novel, got, error: r.error };
  });
}

/** Compile a spec into a self-contained, sandbox-runnable `function bind(task)`. */
export function compileSpec(spec) {
  return [
    'function bind(task) {',
    `  const SPEC = ${JSON.stringify(spec)};`,
    `  const KINDS = ${JSON.stringify(KINDS)};`,
    `  const round = ${round.toString()};`,
    `  ${numberTokens.toString()}`,
    `  ${questionWords.toString()}`,
    `  const shapeOf = ${shapeOf.toString()};`,
    `  ${pick.toString()}`,
    `  ${applySpec.toString()}`,
    '  return applySpec(SPEC, task);',
    '}',
  ].join('\n');
}
