// Receipt verifier: checks a mission receipt WITHOUT the agency, its database, or the network.
// Isomorphic (Node 22+ and modern browsers): only WebCrypto (SHA-256, Ed25519). No imports on purpose, so this one
// file can be handed to anyone, read in a few minutes, and run against a receipt they were given.
//
// A receipt proves, for one mission:
//   1. every included ledger entry is intact (its hash recomputes from its content),
//   2. every entry was signed by the agency key named in the receipt,
//   3. every entry is in the ledger the agency committed to (Merkle inclusion proof to the signed root),
//   4. the root statement (root, size, mission, deliverable hash, time) is signed by the same key,
//   5. the deliverable text you hold is byte-for-byte the one the mission completed with.

/** Must match src/core/util.js canonical() (RFC 8785 JCS compatible): sorted keys, no whitespace, undefined dropped. */
export function canonical(value) {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') {
    if (typeof value === 'number' && !Number.isFinite(value)) return 'null';
    return JSON.stringify(value);
  }
  if (typeof value.toJSON === 'function') return canonical(value.toJSON());
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => new Uint8Array(String(h).match(/.{1,2}/g)?.map((x) => parseInt(x, 16)) || []);
export async function sha256Hex(text) { return hex(await globalThis.crypto.subtle.digest('SHA-256', enc.encode(text))); }

async function sha256Bytes(bytes) { return hex(await globalThis.crypto.subtle.digest('SHA-256', bytes)); }

function concatBytes(...parts) {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

export async function merkleLeafHex(leafHex) {
  return sha256Bytes(concatBytes(new Uint8Array([0x00]), enc.encode(String(leafHex))));
}

export async function merkleNodeHex(leftHex, rightHex) {
  return sha256Bytes(concatBytes(new Uint8Array([0x01]), enc.encode(String(leftHex)), enc.encode(String(rightHex))));
}

function expectedMerkleSteps(seq, size, version) {
  if (!Number.isInteger(seq) || !Number.isInteger(size) || seq < 1 || size < 1 || seq > size) return null;
  const steps = [];
  let idx = seq - 1;
  let len = size;
  while (len > 1) {
    if (version >= 2 && idx % 2 === 0 && idx + 1 === len) {
      idx = Math.floor(idx / 2);
      len = Math.ceil(len / 2);
      continue;
    }
    steps.push(idx % 2 === 1);
    idx = Math.floor(idx / 2);
    len = Math.ceil(len / 2);
  }
  return steps;
}

async function ed25519Verify(publicHex, message, sigHex) {
  try {
    if (!/^[0-9a-f]{64}$/i.test(String(publicHex || '')) || !/^[0-9a-f]{128}$/i.test(String(sigHex || ''))) return false;
    const key = await globalThis.crypto.subtle.importKey('raw', fromHex(publicHex), { name: 'Ed25519' }, false, ['verify']);
    return await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, key, fromHex(sigHex), enc.encode(message));
  } catch { return false; }
}

async function merkleFold(leaf, path, version = 2) {
  if (version >= 2) {
    let h = await merkleLeafHex(leaf);
    for (const step of path) h = step.left ? await merkleNodeHex(step.hash, h) : await merkleNodeHex(h, step.hash);
    return h;
  }
  let h = leaf;
  for (const step of path) h = await sha256Hex(step.left ? step.hash + h : h + step.hash);
  return h;
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([Zz]|[+-](\d{2}):(\d{2}))$/;

export function isValidRfc3339(s) {
  if (typeof s !== 'string') return false;
  const m = RFC3339.exec(s);
  if (!m) return false;
  const y = Number(m[1]), mo = Number(m[2]), d = Number(m[3]);
  const hh = Number(m[4]), mm = Number(m[5]), ss = Number(m[6]);
  if (mo < 1 || mo > 12 || hh > 23 || mm > 59 || ss > 60) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || (y % 400 === 0);
  const maxDay = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  if (d < 1 || d > maxDay) return false;
  if (m[8] !== undefined && (Number(m[8]) > 23 || Number(m[9]) > 59)) return false;
  return true;
}

/**
 * Verify a receipt (supports SVA-ER/1 wire format `spec: "sva-er/1"` and agency v1/v2 `type: "eyeoverthink.receipt"`).
 * deliverable (optional): the text you were given; if omitted, reports `deliverable: "not_checked"`.
 * Returns { ok, outcome, deliverable, clock, checks: [{ name, ok, detail }], summary }.
 */
export async function verifyReceipt(receipt, { deliverable = null } = {}) {
  const checks = [];
  const check = (name, ok, detail = '') => { checks.push({ name, ok: Boolean(ok), detail }); return ok; };
  const isSvaEr = Boolean(receipt && typeof receipt === 'object' && receipt.spec === 'sva-er/1');
  const isLegacy = Boolean(receipt && typeof receipt === 'object' && receipt.type === 'eyeoverthink.receipt');
  if (!isSvaEr && !isLegacy) {
    check('receipt format', false, 'not an sva-er/1 or eyeoverthink.receipt');
    return { ok: false, outcome: 'rejected_malformed', deliverable: 'not_checked', clock: 'verification_failed', checks };
  }
  const pub = receipt.agency?.publicKey;
  const st = receipt.statement;
  const version = isSvaEr ? 2 : Number(receipt.version || 1);
  const expectedStType = isSvaEr ? 'sva-er.statement' : 'eyeoverthink.receipt.statement';
  const clockOk = !isSvaEr || (
    st?.clock != null && typeof st.clock === 'object'
    && ['attested', 'drift', 'unattested'].includes(st.clock.status)
    && isValidRfc3339(st.clock.issuedAt)
  );
  const formatOk = /^[0-9a-f]{64}$/i.test(pub || '')
    && Array.isArray(receipt.entries)
    && st != null && typeof st === 'object' && !Array.isArray(st)
    && st.type === expectedStType
    && typeof st.missionId === 'string' && st.missionId.length > 0
    && /^[0-9a-f]{64}$/i.test(String(st.deliverableSha256 || ''))
    && /^[0-9a-f]{64}$/i.test(String(st.merkleRoot || ''))
    && Number.isInteger(st.size) && st.size >= 1
    && Number.isInteger(st.entries) && st.entries >= 1
    && (version === 1 || version === 2)
    && (!isSvaEr || st.merkle === 'rfc6962-sha256')
    && clockOk;
  check('receipt format', formatOk, isSvaEr ? `sva-er/1, ${Array.isArray(receipt.entries) ? receipt.entries.length : 0} entries` : `version ${receipt.version}, ${Array.isArray(receipt.entries) ? receipt.entries.length : 0} entries`);
  if (!formatOk) {
    return { ok: false, outcome: 'rejected_malformed', deliverable: 'not_checked', clock: 'verification_failed', checks };
  }
  const clockOutcome = isSvaEr ? st.clock.status : (st.clock?.status || 'not_present');

  // 4. Signed root statement.
  const stOk = await ed25519Verify(pub, canonical(st), receipt.statementSig);
  check('root statement signed by the agency key', stOk, stOk ? `ledger size ${st.size}, root ${String(st.merkleRoot).slice(0, 16)}…` : 'signature invalid');

  // Completeness & uniqueness: cannot strip inconvenient entries (e.g. IN_CLOUD / egress_blocked) or duplicate entries.
  const seenSeq = new Set();
  let seqValid = true;
  for (const e of receipt.entries) {
    if (!e || typeof e !== 'object' || !Number.isInteger(e.seq) || e.seq < 1 || e.seq > st.size || seenSeq.has(e.seq)) {
      seqValid = false;
      break;
    }
    seenSeq.add(e.seq);
  }
  const countMatches = receipt.entries.length === st.entries;
  check('entry count matches signed statement (no stripped entries)', countMatches, `${receipt.entries.length}/${st.entries}`);
  check('entry sequence numbers are unique and in range', seqValid, seqValid ? `${seenSeq.size} unique` : 'duplicate or out-of-range seq');

  // 1-3. Each entry: hash, signature, Merkle inclusion (with exact tree depth & left/right parity).
  const merkleVer = st.merkle === 'rfc6962-sha256' || version >= 2 ? 2 : 1;
  let intact = 0, signed = 0, included = 0;
  const bad = [];
  for (const e of receipt.entries) {
    if (!e || typeof e !== 'object') { bad.push('malformed entry'); continue; }
    const h = await sha256Hex(canonical({ seq: e.seq, ts: e.ts, kind: e.kind, actor: e.actor, data: e.data, prev: e.prev }));
    if (h === e.hash) intact++; else bad.push(`#${e.seq} content altered`);
    if (e.signer === pub && await ed25519Verify(pub, e.hash, e.sig)) signed++; else bad.push(`#${e.seq} signature`);
    const proof = Array.isArray(e.proof) ? e.proof : null;
    const expectedSteps = expectedMerkleSteps(e.seq, st.size, merkleVer);
    const shapeOk = Boolean(proof && expectedSteps && proof.length === expectedSteps.length
      && proof.every((step, i) => step && typeof step.hash === 'string' && /^[0-9a-f]{64}$/i.test(step.hash) && Boolean(step.left) === expectedSteps[i]));
    if (shapeOk && await merkleFold(e.hash, proof, merkleVer) === st.merkleRoot) included++; else bad.push(`#${e.seq} not in signed ledger`);
  }
  const n = receipt.entries.length;
  check('entries intact (hash recomputes)', intact === n, `${intact}/${n}`);
  check('entries signed by the agency', signed === n, `${signed}/${n}`);
  check('entries included in the signed ledger (Merkle)', included === n, `${included}/${n}`);

  // Mission binding: every entry belongs to this mission, and the completion entry carries the deliverable hash.
  const mid = st.missionId;
  const belongs = receipt.entries.every((e) => e && typeof e === 'object' && (e.data?.id === mid || e.data?.missionId === mid));
  check('every entry belongs to this mission', belongs, belongs ? mid : 'an entry from another mission was included');
  const done = receipt.entries.find((e) => e && e.kind === 'mission.complete');
  check('mission completion entry present', Boolean(done), done ? `#${done.seq}, score ${done.data?.score}` : 'missing');
  check('completion entry matches the signed deliverable hash', done?.data?.resultHash === st.deliverableSha256, String(st.deliverableSha256).slice(0, 16) + '…');
  let deliverableOutcome = 'not_checked';
  if (deliverable != null) {
    const dh = await sha256Hex(String(deliverable));
    const match = dh === st.deliverableSha256;
    deliverableOutcome = match ? 'verified' : 'verification_failed';
    check('the deliverable you hold is the one the mission produced', match, match ? 'byte-for-byte match' : `your text hashes to ${dh.slice(0, 16)}…`);
  }
  if (bad.length) checks.push({ name: 'problems', ok: false, detail: bad.slice(0, 10).join('; ') });

  // Recomputed summary (from verified entries only, not from the receipt's own claims).
  const of = (k) => receipt.entries.filter((e) => e && e.kind === k);
  const fire = of('edge.inference');
  const summary = {
    toolCalls: of('tool.call').length,
    firebaseCalls: fire.length,
    firebaseInCloud: fire.filter((e) => e.data?.inferenceSource === 'IN_CLOUD').length,
    firebaseOnDevice: fire.filter((e) => e.data?.inferenceSource === 'ON_DEVICE').length,
    sealedCrossings: of('membrane.crossing').length,
    valuesWithheld: of('membrane.crossing').reduce((s, e) => s + (e.data?.total || 0), 0),
    egressBlocked: of('membrane.egress_blocked').length,
  };
  const ok = checks.every((c) => c.ok);
  return {
    ok,
    outcome: ok ? 'verified' : 'verification_failed',
    deliverable: deliverableOutcome,
    clock: clockOutcome,
    checks,
    summary,
  };
}
