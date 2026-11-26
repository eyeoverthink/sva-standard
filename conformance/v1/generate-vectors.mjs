#!/usr/bin/env node
// Deterministic golden conformance vector generator for SVA v1.0 (JCS, RFC 6962 Merkle, AER/1, VSC/1, vsc-revoke/1, EMA/1).
// Uses fixed Ed25519 PKCS#8 RFC 8032 test seeds so vectors.json is 100% reproducible across machines.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(DIR, 'vectors.json');

// RFC 8785 JCS canonicalization
function canonical(value) {
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

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');
const merkleLeaf = (h) => crypto.createHash('sha256').update(Buffer.from([0x00])).update(String(h), 'utf8').digest('hex');
const merkleNode = (l, r) => crypto.createHash('sha256').update(Buffer.from([0x01])).update(String(l), 'utf8').update(String(r), 'utf8').digest('hex');

function buildTree(hashes) {
  const levels = [hashes.map(merkleLeaf)];
  while (levels.at(-1).length > 1) {
    const prev = levels.at(-1), next = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push(i + 1 < prev.length ? merkleNode(prev[i], prev[i + 1]) : prev[i]);
    }
    levels.push(next);
  }
  const root = levels.at(-1)[0];
  const proofOf = (seq) => {
    let idx = seq - 1;
    const p = [];
    for (let l = 0; l < levels.length - 1; l++) {
      const level = levels[l];
      if (idx % 2 === 0 && idx + 1 === level.length) { idx = Math.floor(idx / 2); continue; }
      p.push({ hash: idx % 2 === 0 ? level[idx + 1] : level[idx - 1], left: idx % 2 === 1 });
      idx = Math.floor(idx / 2);
    }
    return p;
  };
  return { root, levels, proofOf };
}

// Deterministic Ed25519 keypair from 32-byte seed hex (PKCS#8 wrapper: 302e020100300506032b657004220420 + 32B seed)
function keyFromSeed(seedHex) {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]);
  const priv = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  const pubHex = Buffer.from(pub.export({ format: 'jwk' }).x, 'base64url').toString('hex');
  const sign = (str) => crypto.sign(null, Buffer.from(str, 'utf8'), priv).toString('hex');
  return { pubHex, sign };
}

const KEY_A = keyFromSeed('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
const KEY_B = keyFromSeed('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');
const HMAC_KEY = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
const hmacTag = (keyHex, val) => crypto.createHmac('sha256', keyHex).update(String(val).toLowerCase(), 'utf8').digest('hex').slice(0, 16);

const vectors = [];
const add = (id, suite, description, expectOk, input) => vectors.push({ id, suite, description, expectOk, input });

// ==================== 1. JCS CANONICALIZATION (10 vectors) ====================
const jcsCases = [
  ['jcs-01', 'Object key sorting', { value: { b: 1, a: 2, c: 0 } }, '{"a":2,"b":1,"c":0}'],
  ['jcs-02', 'Nested objects and arrays preserve array order', { value: { z: [3, { b: true, a: null }, 1], a: 'ok' } }, '{"a":"ok","z":[3,{"a":null,"b":true},1]}'],
  ['jcs-03', 'Empty containers', { value: { b: [], a: {} } }, '{"a":{},"b":[]}'],
  ['jcs-04', 'String escaping (quotes, backslash, newline, tab)', { value: { msg: 'hi "world"\\\n\tend' } }, '{"msg":"hi \\"world\\"\\\\\\n\\tend"}'],
  ['jcs-05', 'Negative zero from raw JSON normalizes to 0', { rawJson: '{"n":-0,"p":0}' }, '{"n":0,"p":0}'],
  ['jcs-06', 'UTF-16 key code-unit sort order', { value: { 'a': 1, 'Z': 2, '0': 3, '_': 4 } }, '{"0":3,"Z":2,"_":4,"a":1}'],
  ['jcs-07', 'Unicode BMP characters and brackets', { value: { ph: '⟦EMAIL_1⟧', euro: '€100' } }, '{"euro":"€100","ph":"⟦EMAIL_1⟧"}'],
  ['jcs-08', 'Booleans, null, integers, decimals', { value: { f: false, t: true, n: null, i: -42, d: 3.14159 } }, '{"d":3.14159,"f":false,"i":-42,"n":null,"t":true}'],
  ['jcs-09', 'RFC 8785 small decimals stay plain down to 1e-6 and switch at 1e-7', { value: { a: 0.0001, b: 0.00001, c: 0.000001, d: 1e-7 } }, '{"a":0.0001,"b":0.00001,"c":0.000001,"d":1e-7}'],
  ['jcs-10', 'RFC 8785 large numbers stay plain up to 1e20 and switch at 1e21', { value: { a: 1e15, b: 1e20, c: 1e21, d: 1.5e21 } }, '{"a":1000000000000000,"b":100000000000000000000,"c":1e+21,"d":1.5e+21}'],
];
for (const [id, desc, inputObj, expected] of jcsCases) {
  add(id, 'jcs', desc, true, { ...inputObj, expected });
}

// ==================== 2. RFC 6962 MERKLE PROOFS (10 vectors) ====================
const sampleHashes = Array.from({ length: 7 }, (_, i) => sha256(`leaf-${i + 1}`));
for (const [id, n, seq] of [
  ['merkle-01', 1, 1],
  ['merkle-02', 2, 2],
  ['merkle-03', 3, 3], // odd promoted leaf!
  ['merkle-04', 4, 2],
  ['merkle-05', 5, 5], // odd promoted leaf!
  ['merkle-06', 7, 4],
]) {
  const t = buildTree(sampleHashes.slice(0, n));
  add(id, 'merkle', `Valid RFC 6962 inclusion proof (seq=${seq} of size=${n})`, true, {
    leaf: sampleHashes[seq - 1], seq, size: n, root: t.root, path: t.proofOf(seq),
  });
}
// Negative Merkle vectors (4)
{
  const t3 = buildTree(sampleHashes.slice(0, 3));
  const t4Dup = buildTree([sampleHashes[0], sampleHashes[1], sampleHashes[2], sampleHashes[2]]);
  add('merkle-07', 'merkle', 'CVE-2012-2459 odd-leaf duplication collision rejected (size 3 root != duplicated size 4)', false, {
    leaf: sampleHashes[2], seq: 4, size: 4, root: t3.root, path: t4Dup.proofOf(4),
  });
  // Second-preimage attack: try passing an internal node hash as a leaf of a 1-leaf tree
  const t2 = buildTree(sampleHashes.slice(0, 2));
  add('merkle-08', 'merkle', 'RFC 6962 0x00/0x01 domain separation blocks internal-node-as-leaf forgery', false, {
    leaf: t2.root, seq: 1, size: 1, root: t2.root, path: [],
  });
  // Flipped left/right orientation
  const badOrient = t3.proofOf(1).map((s, i) => (i === 0 ? { ...s, left: !s.left } : s));
  add('merkle-09', 'merkle', 'Flipped step.left orientation rejected', false, {
    leaf: sampleHashes[0], seq: 1, size: 3, root: t3.root, path: badOrient,
  });
  // Truncated proof depth
  add('merkle-10', 'merkle', 'Truncated proof depth rejected', false, {
    leaf: sampleHashes[0], seq: 1, size: 3, root: t3.root, path: t3.proofOf(1).slice(0, 1),
  });
}

// ==================== 3. AER/1 AGENT EXECUTION RECEIPTS (14 vectors) ====================
function makeAer({ events, missionId, deliverable, clockStatus = 'attested', key = KEY_A, extraLedgerCount = 0 }) {
  const deliverableSha256 = sha256(deliverable);
  const now = '2026-11-26T00:00:00.000Z';
  let prev = '0'.repeat(64);
  const rows = [];
  const all = [...events];
  for (let i = 0; i < extraLedgerCount; i++) all.push({ kind: 'system.noise', actor: 'agency', data: { n: i + 1 } });
  for (let i = 0; i < all.length; i++) {
    const e = { seq: i + 1, ts: now, ...all[i], prev };
    const hash = sha256(canonical(e));
    rows.push({ ...e, hash, sig: key.sign(hash), signer: key.pubHex });
    prev = hash;
  }
  const tree = buildTree(rows.map((r) => r.hash));
  const mine = rows.slice(0, events.length);
  const statement = {
    type: 'aer.statement',
    missionId,
    deliverableSha256,
    merkleRoot: tree.root,
    merkle: 'rfc6962-sha256',
    size: rows.length,
    entries: mine.length,
    clock: { status: clockStatus, issuedAt: now, maxSkewSec: 300 },
  };
  return {
    receipt: {
      spec: 'aer/1',
      agency: { name: 'SVA Conformance Agency', publicKey: key.pubHex },
      statement,
      statementSig: key.sign(canonical(statement)),
      entries: mine.map((r) => ({ ...r, proof: tree.proofOf(r.seq) })),
    },
    deliverable,
  };
}

const delivBase = '# Verified Report\nTotal: 162.00';
const delivHash = sha256(delivBase);
const aerBase = makeAer({
  missionId: 'ms_001',
  deliverable: delivBase,
  extraLedgerCount: 2,
  events: [
    { kind: 'mission.create', actor: 'operator', data: { id: 'ms_001', privacy: 'sealed' } },
    { kind: 'edge.inference', actor: 'edge', data: { missionId: 'ms_001', inferenceSource: 'IN_CLOUD' } },
    { kind: 'mission.complete', actor: 'lumen', data: { id: 'ms_001', score: 0.92, resultHash: delivHash } },
  ],
});
const cloneAer = () => JSON.parse(JSON.stringify(aerBase));

// 6 Valid AER/1 vectors
add('aer-01', 'aer1', 'Valid 3-entry AER/1 receipt in 5-entry ledger with deliverable check', true, cloneAer());
add('aer-02', 'aer1', 'Valid AER/1 receipt verified without optional deliverable', true, { receipt: cloneAer().receipt, deliverable: null });
add('aer-03', 'aer1', 'Valid single-entry AER/1 receipt (size=1, empty Merkle path)', true, makeAer({
  missionId: 'ms_single', deliverable: '42',
  events: [{ kind: 'mission.complete', actor: 'lumen', data: { id: 'ms_single', score: 1, resultHash: sha256('42') } }],
}));
add('aer-04', 'aer1', 'Valid AER/1 receipt with clock.status=unattested', true, makeAer({
  missionId: 'ms_unatt', deliverable: 'ok', clockStatus: 'unattested',
  events: [{ kind: 'mission.complete', actor: 'lumen', data: { id: 'ms_unatt', score: 0.9, resultHash: sha256('ok') } }],
}));
add('aer-05', 'aer1', 'Valid AER/1 receipt with clock.status=drift and key B', true, makeAer({
  missionId: 'ms_drift', deliverable: 'drift-ok', clockStatus: 'drift', key: KEY_B,
  events: [
    { kind: 'tool.call', actor: 'tycho', data: { missionId: 'ms_drift', tool: 'calc' } },
    { kind: 'mission.complete', actor: 'lumen', data: { id: 'ms_drift', score: 0.88, resultHash: sha256('drift-ok') } },
  ],
}));
add('aer-06', 'aer1', 'Valid AER/1 receipt with ON_DEVICE + membrane.crossing entries', true, makeAer({
  missionId: 'ms_hybrid', deliverable: 'hybrid-ok', extraLedgerCount: 1,
  events: [
    { kind: 'membrane.crossing', actor: 'membrane', data: { missionId: 'ms_hybrid', total: 2 } },
    { kind: 'edge.inference', actor: 'edge', data: { missionId: 'ms_hybrid', inferenceSource: 'ON_DEVICE' } },
    { kind: 'mission.complete', actor: 'lumen', data: { id: 'ms_hybrid', score: 0.95, resultHash: sha256('hybrid-ok') } },
  ],
}));

// 8 Invalid AER/1 vectors
{
  let a = cloneAer(); a.deliverable += ' ';
  add('aer-07', 'aer1', 'Deliverable modified by 1 trailing space rejected', false, a);

  a = cloneAer(); a.receipt.entries[2].data.score = 1.0;
  add('aer-08', 'aer1', 'Inflated critic score inside entry data rejected', false, a);

  a = cloneAer(); a.receipt.entries[0].sig = a.receipt.entries[1].sig;
  add('aer-09', 'aer1', 'Swapped entry signature rejected', false, a);

  a = cloneAer(); a.receipt.entries = a.receipt.entries.filter((e) => e.kind !== 'edge.inference');
  add('aer-10', 'aer1', 'Stripped IN_CLOUD entry rejected (statement.entries completeness)', false, a);

  a = cloneAer(); a.receipt.entries = a.receipt.entries.filter((e) => e.kind !== 'edge.inference'); a.receipt.entries.push(cloneAer().receipt.entries[0]);
  add('aer-11', 'aer1', 'Stripped + duplicated entry seq rejected (uniqueness)', false, a);

  a = cloneAer(); a.receipt.entries[0].proof[0].hash = 'f'.repeat(64);
  add('aer-12', 'aer1', 'Forged Merkle proof sibling hash rejected', false, a);

  a = cloneAer(); a.receipt.agency.publicKey = KEY_B.pubHex;
  add('aer-13', 'aer1', 'Swapped agency public key rejected', false, a);

  a = cloneAer(); a.receipt.statement.clock.status = 'fabricated';
  add('aer-14', 'aer1', 'Invalid clock status & broken statementSig rejected', false, a);

  // Red-Team regression: empty clock.issuedAt string signed legitimately must still fail validation
  {
    const badClock = cloneAer();
    badClock.receipt.statement.clock.issuedAt = '';
    badClock.receipt.statementSig = KEY_A.sign(canonical(badClock.receipt.statement));
    add('aer-15', 'aer1', 'Empty string clock.issuedAt rejected even when validly signed', false, badClock);
  }
}

// ==================== 4. VSC/1 SKILL CAPSULES & vsc-revoke/1 (11 vectors) ====================
function makeVsc(overrides = {}, key = KEY_A) {
  const code = overrides.code ?? 'function main({ price, d1, d2 }) { return Math.round(price * (1 - d1) * (1 - d2) * 100) / 100; }';
  const encoding = overrides.encoding ?? 'utf8';
  const codeBuf = encoding === 'base64' ? Buffer.from(code, 'base64') : Buffer.from(code, 'utf8');
  const body = {
    spec: 'vsc/1',
    name: 'sequential_discount',
    version: '1.0.0',
    runtime: 'js-pure-es2022',
    encoding,
    code,
    codeSha256: sha256(codeBuf),
    params: { type: 'object', required: ['price', 'd1', 'd2'] },
    tests: [{ input: { price: 100, d1: 0.2, d2: 0.1 }, output: 72 }],
    capabilities: [],
    signer: key.pubHex,
    ...overrides,
  };
  delete body.sig;
  return { ...body, sig: key.sign(canonical(body)) };
}

function makeRevoke(overrides = {}, key = KEY_B) {
  const body = {
    spec: 'vsc-revoke/1',
    targetCodeSha256: sha256('buggy-skill'),
    kind: 'wrong_output',
    counterexample: { input: { price: 100, d1: 0.2, d2: 0.1 }, expected: 72, observed: 70 },
    issuedAt: '2026-11-26T00:00:00.000Z',
    signer: key.pubHex,
    ...overrides,
  };
  delete body.sig;
  return { ...body, sig: key.sign(canonical(body)) };
}

// Minimal valid WebAssembly binary (magic + version 1: 00 61 73 6d 01 00 00 00)
const VALID_WASM_B64 = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]).toString('base64');
const INVALID_WASM_B64 = Buffer.from([0xde, 0xad, 0xbe, 0xef, 0x01, 0x00, 0x00, 0x00]).toString('base64');

// 3 Valid VSC/1 + vsc-revoke/1 vectors
add('vsc-01', 'vsc1', 'Valid js-pure-es2022 VSC/1 capsule', true, makeVsc());
add('vsc-02', 'vsc1', 'Valid wasm-core-1 VSC/1 capsule with valid WASM magic header', true, makeVsc({
  name: 'wasm_adder', runtime: 'wasm-core-1', encoding: 'base64', code: VALID_WASM_B64,
  codeSha256: sha256(Buffer.from(VALID_WASM_B64, 'base64')),
}));
add('vsc-03', 'vsc1', 'Valid vsc-revoke/1 counterexample tombstone', true, makeRevoke());

// 8 Invalid VSC/1 + vsc-revoke/1 vectors
add('vsc-04', 'vsc1', 'Missing signature (sig: null) rejected (Audit C2)', false, { ...makeVsc(), sig: null });
add('vsc-05', 'vsc1', 'Tampered code rejected (codeSha256 + sig mismatch)', false, { ...makeVsc(), code: 'function main(){return 0;}' });
add('vsc-06', 'vsc1', 'Tampered params rejected (signature mismatch)', false, { ...makeVsc(), params: { type: 'object', required: ['x'] } });
add('vsc-07', 'vsc1', 'Non-empty capabilities array rejected (capability-free rule)', false, makeVsc({ capabilities: ['net:egress'] }));
add('vsc-08', 'vsc1', 'Unsupported runtime shell-bash rejected', false, makeVsc({ runtime: 'shell-bash' }));
add('vsc-09', 'vsc1', 'Invalid WASM magic header rejected', false, makeVsc({
  name: 'bad_wasm', runtime: 'wasm-core-1', encoding: 'base64', code: INVALID_WASM_B64,
  codeSha256: sha256(Buffer.from(INVALID_WASM_B64, 'base64')),
}));
add('vsc-10', 'vsc1', 'Prototype-pollution skill name __proto__ rejected', false, makeVsc({ name: '__proto__' }));
add('vsc-11', 'vsc1', 'vsc-revoke/1 tombstone missing counterexample.input rejected', false, makeRevoke({ counterexample: {} }));
add('vsc-12', 'vsc1', 'Malformed base64 in wasm-core-1 capsule rejected identically across runtimes', false, makeVsc({
  name: 'bad_b64_wasm', runtime: 'wasm-core-1', encoding: 'base64', code: '!!!not-valid-base64!!!',
  codeSha256: sha256(Buffer.from('!!!not-valid-base64!!!', 'base64')),
}));
add('vsc-13', 'vsc1', 'Mismatched runtime/encoding (wasm-core-1 with utf8) rejected', false, makeVsc({
  name: 'wasm_utf8_mismatch', runtime: 'wasm-core-1', encoding: 'utf8', code: '\x00asm\x01\x00\x00\x00',
  codeSha256: sha256(Buffer.from('\x00asm\x01\x00\x00\x00', 'utf8')),
}));

// ==================== 5. EMA/1 EGRESS MEMBRANE ATTESTATIONS (11 vectors) ====================
function makeEma({ mode = 'SEALED_EGRESS', outboundPayload = 'Patient ⟦PERSON_1⟧ (⟦SSN_1⟧) via ⟦EMAIL_1⟧.', originals = [], hmacKeyHex = HMAC_KEY, airgap = null, overrides = {}, key = KEY_A } = {}) {
  const payload = mode === 'ONLY_ON_DEVICE' ? '' : outboundPayload;
  const counts = {};
  const tags = [];
  for (const o of originals) {
    counts[o.type] = (counts[o.type] || 0) + 1;
    tags.push({ type: o.type, tag: hmacTag(hmacKeyHex, o.value) });
  }
  const body = {
    spec: 'ema/1',
    mode,
    provider: mode === 'ONLY_ON_DEVICE' ? 'local-ollama' : 'firebase-edge',
    model: mode === 'ONLY_ON_DEVICE' ? 'llama3.2:latest' : 'gemini-2.5-flash',
    outboundSha256: sha256(Buffer.from(payload, 'utf8')),
    egressBytes: Buffer.byteLength(payload, 'utf8'),
    withheld: counts,
    totalWithheld: tags.length,
    tags,
    audit: 'clean',
    strictNer: true,
    ...(airgap ? { airgap } : {}),
    issuedAt: '2026-11-26T00:00:00.000Z',
    signer: key.pubHex,
    ...overrides,
  };
  delete body.sig;
  return {
    attestation: { ...body, sig: key.sign(canonical(body)) },
    outboundPayload: payload,
    hmacKeyHex,
    originals,
  };
}

const sampleOriginals = [
  { type: 'PERSON', value: 'Dr. Elena Morales' },
  { type: 'SSN', value: '123-45-6789' },
  { type: 'EMAIL', value: 'elena@northstar.org' },
];

// 4 Valid EMA/1 vectors
add('ema-01', 'ema1', 'Valid SEALED_EGRESS attestation with verified HMAC tags and clean payload', true, makeEma({ originals: sampleOriginals }));
add('ema-02', 'ema1', 'Valid ONLY_ON_DEVICE attestation with 0 egress bytes and airgap NIC=0 proof', true, makeEma({
  mode: 'ONLY_ON_DEVICE', originals: [], airgap: { networkInterfaces: 0, verified: true },
}));
add('ema-03', 'ema1', 'Valid SEALED_EGRESS verified without local secret key (wire-only mode)', true, (() => {
  const m = makeEma({ originals: sampleOriginals });
  return { attestation: m.attestation, outboundPayload: m.outboundPayload, hmacKeyHex: null, originals: [] };
})());
add('ema-04', 'ema1', 'Valid SEALED_EGRESS with phone number normalized safely absent', true, makeEma({
  outboundPayload: 'Call ⟦PHONE_1⟧ immediately.',
  originals: [{ type: 'PHONE', value: '+1 (512) 555-0194' }],
}));

// 7 Invalid EMA/1 vectors
{
  let m = makeEma({ originals: sampleOriginals });
  m.outboundPayload += ' extra';
  add('ema-05', 'ema1', 'Outbound payload modified after attestation rejected (outboundSha256 mismatch)', false, m);

  m = makeEma({ originals: sampleOriginals });
  m.attestation.sig = '0'.repeat(128);
  add('ema-06', 'ema1', 'Forged EMA/1 Ed25519 signature rejected', false, m);

  m = makeEma({ originals: sampleOriginals });
  m.attestation.tags[0].tag = 'deadbeef01234567';
  add('ema-07', 'ema1', 'Tampered HMAC correlation tag rejected', false, m);

  m = makeEma({
    outboundPayload: 'Patient ⟦PERSON_1⟧ leaked elena@northstar.org in body.',
    originals: sampleOriginals,
  });
  add('ema-08', 'ema1', 'Raw plaintext email leak in outbound payload caught by audit', false, m);

  m = makeEma({
    outboundPayload: 'Patient ⟦PERSON_1⟧ digits 123456789 leaked without dashes.',
    originals: sampleOriginals,
  });
  add('ema-09', 'ema1', 'Digit-squeezed SSN leak (123456789) caught by egress audit', false, m);

  m = makeEma({ originals: sampleOriginals, overrides: { audit: 'leaked' } });
  add('ema-10', 'ema1', 'Non-clean audit status rejected', false, m);

  m = makeEma({
    mode: 'ONLY_ON_DEVICE', originals: [],
    airgap: { networkInterfaces: 2, verified: false },
    overrides: { egressBytes: 12 },
  });
  add('ema-11', 'ema1', 'ONLY_ON_DEVICE with egressBytes > 0 or non-zero NICs rejected', false, m);

  // Red-Team regressions: 2^32 integer truncation, negative-count cancellation, per-type mismatch
  m = makeEma({
    mode: 'ONLY_ON_DEVICE', originals: [],
    airgap: { networkInterfaces: 4294967296, verified: true },
    overrides: { egressBytes: 4294967296 },
  });
  add('ema-12', 'ema1', '64-bit 2^32 egressBytes / networkInterfaces does NOT truncate to 0 in Java', false, m);

  m = makeEma({
    originals: [{ type: 'SSN', value: '123-45-6789' }],
    overrides: { withheld: { EMAIL: -1, SSN: 1000000001 }, totalWithheld: 1 },
  });
  add('ema-13', 'ema1', 'Negative withheld count cancellation attack rejected', false, m);

  m = makeEma({
    originals: [{ type: 'SSN', value: '123-45-6789' }],
    overrides: { withheld: { EMAIL: 1 }, totalWithheld: 1 },
  });
  add('ema-14', 'ema1', 'Per-type withheld/tags mismatch (withheld EMAIL vs tag SSN) rejected', false, m);
}

// ==================== 6. PHASE 27/28: CROSS-RUNTIME FUEL-METERED WASM EXECUTION (14 vectors) ====================
function uleb(n) {
  const out = [];
  do { let b = n & 0x7f; n >>>= 7; if (n !== 0) b |= 0x80; out.push(b); } while (n !== 0);
  return out;
}
function sleb(n) {
  const out = [];
  let more = true;
  while (more) {
    let b = n & 0x7f;
    n >>= 7;
    if ((n === 0 && (b & 0x40) === 0) || (n === -1 && (b & 0x40) !== 0)) more = false;
    else b |= 0x80;
    out.push(b);
  }
  return out;
}
function f64Bytes(val) {
  const buf = Buffer.alloc(8);
  buf.writeDoubleLE(val, 0);
  return [...buf];
}
function wasmSection(id, payload) { return [id, ...uleb(payload.length), ...payload]; }
function encodeWasmFunc({ params = [], result = 0x7f, locals = [], memory = null, data = [], ops }) {
  const typeSec = wasmSection(1, [1, 0x60, ...uleb(params.length), ...params, 1, result]);
  const funcSec = wasmSection(3, [1, 0]);
  const memSec = memory
    ? wasmSection(5, memory.max != null ? [1, 0x01, ...uleb(memory.min), ...uleb(memory.max)] : [1, 0x00, ...uleb(memory.min)])
    : [];
  const exportSec = wasmSection(7, [1, 4, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0]); // export "main" -> func 0
  const localGroups = locals.length > 0 ? [locals.length, ...locals.flatMap(([count, t]) => [...uleb(count), t])] : [0];
  const body = [...localGroups, ...ops, 0x0b];
  const codeSec = wasmSection(10, [1, ...uleb(body.length), ...body]);
  const dataSec = data.length > 0
    ? wasmSection(11, [data.length, ...data.flatMap(({ offset, bytes }) => [0x00, 0x41, ...sleb(offset), 0x0b, ...uleb(bytes.length), ...bytes])])
    : [];
  return Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, ...typeSec, ...funcSec, ...memSec, ...exportSec, ...codeSec, ...dataSec]);
}
function encodeWasmI32Func({ paramCount, extraI32Locals = 0, ops }) {
  return encodeWasmFunc({
    params: Array(paramCount).fill(0x7f),
    result: 0x7f,
    locals: extraI32Locals > 0 ? [[extraI32Locals, 0x7f]] : [],
    ops,
  });
}
function makeWasmCapsule(name, wasmBytes, tests = [{ input: [1], output: 1 }]) {
  const b64 = wasmBytes.toString('base64');
  return makeVsc({ name, runtime: 'wasm-core-1', encoding: 'base64', code: b64, codeSha256: sha256(wasmBytes), tests });
}

// 1. discount_cents(price, pct1, pct2) = ((price * (100 - pct1)) / 100) * (100 - pct2) / 100
const WASM_DISCOUNT = encodeWasmI32Func({
  paramCount: 3,
  ops: [
    0x20, 0, 0x41, ...sleb(100), 0x20, 1, 0x6b, 0x6c, 0x41, ...sleb(100), 0x6d,
    0x41, ...sleb(100), 0x20, 2, 0x6b, 0x6c, 0x41, ...sleb(100), 0x6d,
  ],
});
const CAP_DISCOUNT = makeWasmCapsule('wasm_discount_cents', WASM_DISCOUNT, [{ input: [10000, 20, 10], output: 7200 }]);

// 2. tax_and_split(subtotal, taxPct, people) = ((subtotal * (100 + taxPct)) / 100) / people
const WASM_TAX_SPLIT = encodeWasmI32Func({
  paramCount: 3,
  ops: [
    0x20, 0, 0x41, ...sleb(100), 0x20, 1, 0x6a, 0x6c, 0x41, ...sleb(100), 0x6d,
    0x20, 2, 0x6d,
  ],
});
const CAP_TAX_SPLIT = makeWasmCapsule('wasm_tax_split', WASM_TAX_SPLIT, [{ input: [10000, 8, 4], output: 2700 }]);

// 3. sum_to_n(n) using real block/loop/br_if/local.set control flow
const WASM_SUM_TO_N = encodeWasmI32Func({
  paramCount: 1,
  extraI32Locals: 2, // local 1 = acc, local 2 = i
  ops: [
    0x41, ...sleb(0), 0x21, 1,
    0x41, ...sleb(1), 0x21, 2,
    0x02, 0x40, // block
      0x03, 0x40, // loop
        0x20, 2, 0x20, 0, 0x4a, 0x0d, 1, // if i > n: br 1
        0x20, 1, 0x20, 2, 0x6a, 0x21, 1, // acc += i
        0x20, 2, 0x41, ...sleb(1), 0x6a, 0x21, 2, // i += 1
        0x0c, 0, // br 0
      0x0b,
    0x0b,
    0x20, 1,
  ],
});
const CAP_SUM_TO_N = makeWasmCapsule('wasm_sum_to_n', WASM_SUM_TO_N, [{ input: [10], output: 55 }]);

// 4. infinite_loop_dos(x): adversarial unbounded loop stopped by fuel metering
const WASM_DOS_LOOP = encodeWasmI32Func({
  paramCount: 1,
  ops: [0x03, 0x40, 0x0c, 0, 0x0b, 0x20, 0],
});
const CAP_DOS_LOOP = makeWasmCapsule('wasm_infinite_dos', WASM_DOS_LOOP, [{ input: [1], output: 1 }]);

// 5. buggy_discount(price, pct) = price - pct (faulty!) paired with signed vsc-revoke/1 tombstone
const WASM_BUGGY = encodeWasmI32Func({
  paramCount: 2,
  ops: [0x20, 0, 0x20, 1, 0x6b],
});
const CAP_BUGGY = makeWasmCapsule('wasm_buggy_discount', WASM_BUGGY, [{ input: [100, 0], output: 100 }]);
const REV_BUGGY = makeRevoke({
  targetCodeSha256: CAP_BUGGY.codeSha256,
  kind: 'wrong_output',
  counterexample: { input: [10000, 20], expected: 8000, observed: 9980 },
});

// 6. corrupt_wasm: valid 8-byte magic+version header followed by corrupt truncated section bytes
const WASM_CORRUPT = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x7f, 0xff]);
const CAP_CORRUPT = makeWasmCapsule('wasm_corrupt_section', WASM_CORRUPT, [{ input: [1], output: 1 }]);

// 7. SVA v1.2 f64 compound discount: price * (1.0 - d1) * (1.0 - d2)
const WASM_F64_DISCOUNT = encodeWasmFunc({
  params: [0x7c, 0x7c, 0x7c],
  result: 0x7c,
  ops: [
    0x20, 0,
    0x44, ...f64Bytes(1.0), 0x20, 1, 0xa1, 0xa2,
    0x44, ...f64Bytes(1.0), 0x20, 2, 0xa1, 0xa2,
  ],
});
const CAP_F64_DISCOUNT = makeWasmCapsule('wasm_f64_discount', WASM_F64_DISCOUNT, [{ input: [240.0, 0.25, 0.1], output: 162.0 }]);

// 8. SVA v1.2 f64 harmonic mean (round-trip average speed): (2.0 * v1 * v2) / (v1 + v2)
const WASM_F64_HARMONIC = encodeWasmFunc({
  params: [0x7c, 0x7c],
  result: 0x7c,
  ops: [
    0x44, ...f64Bytes(2.0), 0x20, 0, 0xa2, 0x20, 1, 0xa2,
    0x20, 0, 0x20, 1, 0xa0,
    0xa3,
  ],
});
const CAP_F64_HARMONIC = makeWasmCapsule('wasm_f64_harmonic_mean', WASM_F64_HARMONIC, [{ input: [60.0, 40.0], output: 48.0 }]);

// 9. SVA v1.2 linear memory + active data segment + i32.load/i32.store
const DATA_INTS = Buffer.alloc(16);
DATA_INTS.writeInt32LE(10, 0);
DATA_INTS.writeInt32LE(20, 4);
DATA_INTS.writeInt32LE(30, 8);
DATA_INTS.writeInt32LE(40, 12);
const WASM_MEM_SUM = encodeWasmFunc({
  params: [0x7f], // count n
  result: 0x7f,
  locals: [[2, 0x7f]], // local 1 = acc, local 2 = i
  memory: { min: 1, max: 2 },
  data: [{ offset: 0, bytes: [...DATA_INTS] }],
  ops: [
    0x41, ...sleb(0), 0x21, 1,
    0x41, ...sleb(0), 0x21, 2,
    0x02, 0x40,
      0x03, 0x40,
        0x20, 2, 0x20, 0, 0x4e, 0x0d, 1, // if i >= n: br 1
        0x20, 1,
        0x20, 2, 0x41, ...sleb(4), 0x6c, 0x28, 0x02, 0x00, // i32.load align=2 offset=0 at i*4
        0x6a, 0x21, 1,
        0x20, 2, 0x41, ...sleb(1), 0x6a, 0x21, 2,
        0x0c, 0,
      0x0b,
    0x0b,
    // Store acc at offset 64, reload and return
    0x41, ...sleb(64), 0x20, 1, 0x36, 0x02, 0x00,
    0x41, ...sleb(64), 0x28, 0x02, 0x00,
  ],
});
const CAP_MEM_SUM = makeWasmCapsule('wasm_mem_sum', WASM_MEM_SUM, [{ input: [4], output: 100 }]);

// 10. SVA v1.2 linear memory f64.store/f64.load + memory.grow + memory.size + f64.convert_i32_s
const WASM_MEM_GROW_F64 = encodeWasmFunc({
  params: [0x7c], // base f64
  result: 0x7c,
  memory: { min: 1, max: 4 },
  ops: [
    // store param 0 at offset 0
    0x41, ...sleb(0), 0x20, 0, 0x39, 0x03, 0x00,
    // grow memory by 1 page (returns old pages = 1, discard via local? No, convert and add!)
    0x41, ...sleb(1), 0x40, 0x00, 0xb7, // f64(oldPages = 1.0)
    0x3f, 0x00, 0xb7, // f64(newPages = 2.0)
    0xa0, // 3.0
    0x41, ...sleb(0), 0x2b, 0x03, 0x00, // reload f64 param
    0xa0, // 3.0 + param
  ],
});
const CAP_MEM_GROW_F64 = makeWasmCapsule('wasm_mem_grow_f64', WASM_MEM_GROW_F64, [{ input: [0.5], output: 3.5 }]);

// 11. SVA v1.2 out-of-bounds linear memory read traps deterministically
const WASM_MEM_OOB = encodeWasmFunc({
  params: [0x7f], // addr
  result: 0x7f,
  memory: { min: 1, max: 1 },
  ops: [0x20, 0, 0x28, 0x02, 0x00],
});
const CAP_MEM_OOB = makeWasmCapsule('wasm_mem_oob', WASM_MEM_OOB, [{ input: [0], output: 0 }]);

// 12. SVA v1.2 f64 NaN/overflow -> i32.trunc_f64_s traps deterministically
const WASM_TRUNC_TRAP = encodeWasmFunc({
  params: [0x7c, 0x7c],
  result: 0x7f,
  ops: [0x20, 0, 0x20, 1, 0xa3, 0xaa], // (a / b) -> i32.trunc_f64_s
});
const CAP_TRUNC_TRAP = makeWasmCapsule('wasm_f64_trunc_trap', WASM_TRUNC_TRAP, [{ input: [10.0, 2.0], output: 5 }]);

add('wasm-01', 'wasm_exec', 'Cross-runtime WASM discount_cents(10000, 20, 10) == 7200 (V8 == WebCrypto == Java)', true, {
  capsule: CAP_DISCOUNT, args: [10000, 20, 10], expectOutput: 7200, fuelLimit: 1000,
});
add('wasm-02', 'wasm_exec', 'Cross-runtime WASM discount_cents(24000, 25, 10) == 16200', true, {
  capsule: CAP_DISCOUNT, args: [24000, 25, 10], expectOutput: 16200, fuelLimit: 1000,
});
add('wasm-03', 'wasm_exec', 'Cross-runtime WASM tax_and_split(10000, 8, 4) == 2700', true, {
  capsule: CAP_TAX_SPLIT, args: [10000, 8, 4], expectOutput: 2700, fuelLimit: 1000,
});
add('wasm-04', 'wasm_exec', 'Cross-runtime WASM tax_and_split(10000, 8, 0) traps deterministically on divide-by-zero', true, {
  capsule: CAP_TAX_SPLIT, args: [10000, 8, 0], expectTrap: 'div_by_zero', fuelLimit: 1000,
});
add('wasm-05', 'wasm_exec', 'Cross-runtime WASM loop/branch sum_to_n(10) == 55', true, {
  capsule: CAP_SUM_TO_N, args: [10], expectOutput: 55, fuelLimit: 1000,
});
add('wasm-06', 'wasm_exec', 'Adversarial infinite-loop WASM DoS capsule trapped by deterministic fuel metering', true, {
  capsule: CAP_DOS_LOOP, args: [1], expectTrap: 'fuel_exhausted', fuelLimit: 500,
});
add('wasm-07', 'wasm_exec', 'End-to-end zero-rumor vsc-revoke/1 locally reproduces buggy WASM output (9980 != 8000)', true, {
  capsule: CAP_BUGGY, revocation: REV_BUGGY, fuelLimit: 1000,
});
add('wasm-08', 'wasm_exec', 'Corrupt WASM section bytes rejected by full structural validation despite valid 8-byte header', false, {
  capsule: CAP_CORRUPT, args: [1], expectOutput: 1, fuelLimit: 1000,
});
add('wasm-09', 'wasm_exec', 'SVA v1.2 f64 compound discount(240.0, 0.25, 0.1) == 162.0 bit-identical across V8, WebCrypto, Java', true, {
  capsule: CAP_F64_DISCOUNT, args: [240.0, 0.25, 0.1], expectOutput: 162.0, fuelLimit: 1000,
});
add('wasm-10', 'wasm_exec', 'SVA v1.2 f64 harmonic mean(60.0, 40.0) == 48.0 bit-identical across V8, WebCrypto, Java', true, {
  capsule: CAP_F64_HARMONIC, args: [60.0, 40.0], expectOutput: 48.0, fuelLimit: 1000,
});
add('wasm-11', 'wasm_exec', 'SVA v1.2 linear memory active data segment + i32.load/i32.store sum(4) == 100', true, {
  capsule: CAP_MEM_SUM, args: [4], expectOutput: 100, fuelLimit: 1000,
});
add('wasm-12', 'wasm_exec', 'SVA v1.2 linear memory f64.store/f64.load + memory.grow + memory.size(0.5) == 3.5', true, {
  capsule: CAP_MEM_GROW_F64, args: [0.5], expectOutput: 3.5, fuelLimit: 1000,
});
add('wasm-13', 'wasm_exec', 'SVA v1.2 out-of-bounds linear memory load (addr=65536 on 1 page) traps deterministically (mem_oob)', true, {
  capsule: CAP_MEM_OOB, args: [65536], expectTrap: 'mem_oob', fuelLimit: 1000,
});
add('wasm-14', 'wasm_exec', 'SVA v1.2 f64 NaN -> i32.trunc_f64_s (0.0/0.0) traps deterministically (invalid_conversion)', true, {
  capsule: CAP_TRUNC_TRAP, args: [0.0, 0.0], expectTrap: 'invalid_conversion', fuelLimit: 1000,
});

const doc = {
  specVersion: 'sva-conformance/1.2',
  generatedWith: 'node:' + process.version,
  total: vectors.length,
  suites: {
    jcs: vectors.filter((v) => v.suite === 'jcs').length,
    merkle: vectors.filter((v) => v.suite === 'merkle').length,
    aer1: vectors.filter((v) => v.suite === 'aer1').length,
    vsc1: vectors.filter((v) => v.suite === 'vsc1').length,
    ema1: vectors.filter((v) => v.suite === 'ema1').length,
    wasm_exec: vectors.filter((v) => v.suite === 'wasm_exec').length,
  },
  vectors,
};

fs.writeFileSync(OUT, JSON.stringify(doc, null, 2) + '\n');
console.log(`Generated ${doc.total} golden vectors -> ${OUT}`, doc.suites);
