#!/usr/bin/env node
// Deterministic generator for the joint AER-1 (draft-zambo-aer1-26, kit 1.6.1) <-> SVA-ER/1
// clock-attestation & key-binding interop vector suite.
// Uses fixed RFC 8032 Ed25519 seeds matching conformance/v1/generate-vectors.mjs.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonical } from '../../v1/runners/node-verify.mjs';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.join(DIR, 'vectors.json');

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
  return { root, proofOf };
}

function keyFromSeed(seedHex) {
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]);
  const priv = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv);
  const pubHex = Buffer.from(pub.export({ format: 'jwk' }).x, 'base64url').toString('hex');
  return {
    pubHex,
    sign: (str) => crypto.sign(null, Buffer.from(str, 'utf8'), priv).toString('hex'),
  };
}

const KEY_A = keyFromSeed('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
const KEY_B = keyFromSeed('4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb');

function makeSvaEr({ events, missionId, deliverable, clockStatus = 'attested', issuedAt = '2026-11-26T00:00:00.000Z', key = KEY_A, agencyName = 'SVA Conformance Agency' }) {
  const deliverableSha256 = sha256(deliverable);
  let prev = '0'.repeat(64);
  const rows = [];
  for (let i = 0; i < events.length; i++) {
    const e = { seq: i + 1, ts: issuedAt, ...events[i], prev };
    const hash = sha256(canonical(e));
    rows.push({ ...e, hash, sig: key.sign(hash), signer: key.pubHex });
    prev = hash;
  }
  const tree = buildTree(rows.map((r) => r.hash));
  const statement = {
    type: 'sva-er.statement',
    missionId,
    deliverableSha256,
    merkleRoot: tree.root,
    merkle: 'rfc6962-sha256',
    size: rows.length,
    entries: rows.length,
    clock: { status: clockStatus, issuedAt, maxSkewSec: 300 },
  };
  return {
    receipt: {
      spec: 'sva-er/1',
      agency: { name: agencyName, publicKey: key.pubHex },
      statement,
      statementSig: key.sign(canonical(statement)),
      entries: rows.map((r) => ({ ...r, proof: tree.proofOf(r.seq) })),
    },
    deliverable,
  };
}

// AER-1 v0.4 canonical JSON (keys sorted by Unicode code point, ASCII escaping) + Section 3.1 metadata_hash
function aer1Canonical(val) {
  if (Array.isArray(val)) return '[' + val.map(aer1Canonical).join(',') + ']';
  if (val !== null && typeof val === 'object') {
    const keys = Object.keys(val).sort((a, b) => {
      const aa = Array.from(a), bb = Array.from(b);
      for (let i = 0; i < Math.min(aa.length, bb.length); i++) {
        const d = aa[i].codePointAt(0) - bb[i].codePointAt(0);
        if (d) return d;
      }
      return aa.length - bb.length;
    });
    return '{' + keys.map((k) => JSON.stringify(k) + ':' + aer1Canonical(val[k])).join(',') + '}';
  }
  return JSON.stringify(val);
}

function makeAer1V04({ id, createdAt, tool, provenanceClass = 'EXECUTED BY SVA-AGENCY', inputs, outputs }) {
  const payloadObj = {
    inputs,
    issuer_claims: { provenance_class: provenanceClass },
    outputs,
    receipt_schema_version: '0.4',
    tool: tool.name,
  };
  const payloadBytes = Buffer.from(aer1Canonical(payloadObj), 'utf8');
  const outputHash = 'sha256:' + sha256(payloadBytes);
  const metaBlock = {
    created_at: createdAt,
    id,
    output_hash: outputHash,
    provenance_class: provenanceClass,
    receipt_schema_version: '0.4',
    tool: { name: tool.name, scope: tool.scope, version: tool.version },
  };
  const metadataHash = 'sha256:' + sha256(Buffer.from(aer1Canonical(metaBlock), 'utf8'));
  return {
    id,
    receipt_schema_version: '0.4',
    created_at: createdAt,
    tool,
    provenance_class: provenanceClass,
    canonical_bytes: payloadBytes.toString('base64'),
    output_hash: outputHash,
    metadata_hash: metadataHash,
    verification_status: 'verified',
  };
}

// 1. interop-01: svaer-04 (clock.status = unattested, KEY_A) <-> AER-1 v0.4 (clock/key fields absent)
const v01Sva = makeSvaEr({
  missionId: 'ms_unatt',
  deliverable: 'ok',
  clockStatus: 'unattested',
  key: KEY_A,
  events: [{ kind: 'mission.complete', actor: 'lumen', data: { id: 'ms_unatt', score: 0.9, resultHash: sha256('ok') } }],
});
const v01Aer = makeAer1V04({
  id: '11111111-1111-4111-8111-111111111104',
  createdAt: '2026-11-26T00:00:00.000Z',
  tool: { name: 'mission.complete', version: '1.0.0', scope: 'local-unattested-clock' },
  inputs: { missionId: 'ms_unatt' },
  outputs: { deliverable: 'ok', score: 0.9 },
});

// 2. interop-02: svaer-05 (clock.status = drift, KEY_B) <-> AER-1 v0.4 (clock/key fields absent)
const v02Sva = makeSvaEr({
  missionId: 'ms_drift',
  deliverable: 'drift-ok',
  clockStatus: 'drift',
  key: KEY_B,
  events: [
    { kind: 'tool.call', actor: 'tycho', data: { missionId: 'ms_drift', tool: 'calc' } },
    { kind: 'mission.complete', actor: 'lumen', data: { id: 'ms_drift', score: 0.88, resultHash: sha256('drift-ok') } },
  ],
});
const v02Aer = makeAer1V04({
  id: '11111111-1111-4111-8111-111111111105',
  createdAt: '2026-11-26T00:00:00.000Z',
  tool: { name: 'calc', version: '1.0.0', scope: 'local-drifted-clock' },
  inputs: { missionId: 'ms_drift' },
  outputs: { deliverable: 'drift-ok', score: 0.88 },
});

// 3. interop-03: key-binding divergence (svaer-05 with swapped agency.publicKey KEY_B -> KEY_A)
const v03Sva = JSON.parse(JSON.stringify(v02Sva));
v03Sva.receipt.agency.publicKey = KEY_A.pubHex;
const v03AerTampered = { ...v02Aer, created_at: '2026-11-26T00:05:00.000Z' }; // breaks metadata_hash

// 4. interop-04: AER-1 corpus valid/bound-04.json expressed in SVA-ER/1 (exercising attested clock + KEY_A binding)
const bound04Aer = {
  id: '294911b8-ac49-4f63-99f4-129a7e6d9c18',
  receipt_schema_version: '0.4',
  created_at: '2026-10-08T12:00:00.000Z',
  tool: { name: 'get_weather', version: '1.0.0', scope: 'public' },
  provenance_class: 'EXECUTED BY ZAMBO',
  canonical_bytes: 'eyJpbnB1dHMiOnsiY2l0eSI6IkF1c3RpbiJ9LCJpc3N1ZXJfY2xhaW1zIjp7InByb3ZlbmFuY2VfY2xhc3MiOiJFWEVDVVRFRCBCWSBaQU1CTyJ9LCJvdXRwdXRzIjoic3VubnksIDc1RiIsInJlY2VpcHRfc2NoZW1hX3ZlcnNpb24iOiIwLjQiLCJ0b29sIjoiZ2V0X3dlYXRoZXIifQ==',
  output_hash: 'sha256:3f113a9b490bc0b2a22b56a22b48cd9396b2e6a8082824cf56ca85fe53e795d6',
  metadata_hash: 'sha256:0131154d838fbe47bb5f0db3b2c859f93a3ebe0d47ce027a9fdc013d4b4b25fd',
  verification_status: 'verified',
};
const bound04Deliverable = 'sunny, 75F';
const v04Sva = makeSvaEr({
  missionId: 'aer1-bound-04',
  deliverable: bound04Deliverable,
  clockStatus: 'attested',
  issuedAt: '2026-10-08T12:00:00.000Z',
  key: KEY_A,
  events: [
    { kind: 'tool.call', actor: 'edge', data: { missionId: 'aer1-bound-04', tool: 'get_weather', inputs: { city: 'Austin' } } },
    { kind: 'mission.complete', actor: 'edge', data: { id: 'aer1-bound-04', aer1Id: bound04Aer.id, resultHash: sha256(bound04Deliverable) } },
  ],
});

// 5. interop-05: Real-world hardware case — FMP/1 offline Raspberry Pi mesh (no RTC -> clock_trusted=false)
const fmpDeliverable = 'CUSTODY_DELIVERED:node-barn-pi:seq=42:hops=3';
const v05Sva = makeSvaEr({
  missionId: 'fmp1-custody-42',
  deliverable: fmpDeliverable,
  clockStatus: 'unattested',
  issuedAt: '2026-11-26T00:00:00.000Z',
  key: KEY_B,
  agencyName: 'FMP/1 Offline Mesh Relay (no RTC)',
  events: [
    { kind: 'mesh.custody_hold', actor: 'relay-1', data: { missionId: 'fmp1-custody-42', clockTrusted: false, partitionSec: 612 } },
    { kind: 'mission.complete', actor: 'relay-1', data: { id: 'fmp1-custody-42', resultHash: sha256(fmpDeliverable) } },
  ],
});
const v05Aer = makeAer1V04({
  id: '11111111-1111-4111-8111-111111111106',
  createdAt: '2026-11-26T00:00:00.000Z',
  tool: { name: 'fmp1.custody_deliver', version: '1.0.0', scope: 'offline-mesh-no-rtc' },
  inputs: { custodySeq: 42, partitionSec: 612 },
  outputs: { status: fmpDeliverable },
});

// 6. interop-06: AER-1-side authoring of aer-04 (handover.wrap recorded on a host with no trusted clock) <-> SVA-ER/1 twin (clock.status = unattested, KEY_A)
const v06Sva = makeSvaEr({
  missionId: 'aer1-04-handover',
  deliverable: 'handover:aer1-04:steps=3',
  clockStatus: 'unattested',
  key: KEY_A,
  agencyName: 'zambodotdev',
  events: [
    { kind: 'tool.call', actor: 'rambo', data: { missionId: 'aer1-04-handover', tool: 'handover.wrap' } },
    { kind: 'mission.complete', actor: 'rambo', data: { id: 'aer1-04-handover', resultHash: sha256('handover:aer1-04:steps=3') } },
  ],
});
const v06Aer = makeAer1V04({
  id: '22222222-2222-4222-8222-222222222204',
  createdAt: '2026-11-26T00:00:00.000Z',
  tool: { name: 'handover.wrap', version: '1.0.0', scope: 'agent-handover' },
  provenanceClass: 'EXECUTED BY ZAMBO',
  inputs: { job: 'aer1-04-handover' },
  outputs: { deliverable: 'handover:aer1-04:steps=3', steps: 3 },
});

// 7. interop-07: AER-1-side authoring of aer-05 (receipt.verify under a drifted clock) <-> SVA-ER/1 twin (clock.status = drift, KEY_B)
const v07Sva = makeSvaEr({
  missionId: 'aer1-05-attribution',
  deliverable: 'verified:aer1-05-target',
  clockStatus: 'drift',
  key: KEY_B,
  agencyName: 'zambodotdev',
  events: [
    { kind: 'tool.call', actor: 'rambo', data: { missionId: 'aer1-05-attribution', tool: 'receipt.verify' } },
    { kind: 'mission.complete', actor: 'rambo', data: { id: 'aer1-05-attribution', resultHash: sha256('verified:aer1-05-target') } },
  ],
});
const v07Aer = makeAer1V04({
  id: '22222222-2222-4222-8222-222222222205',
  createdAt: '2026-11-26T00:00:00.000Z',
  tool: { name: 'receipt.verify', version: '1.0.0', scope: 'cross-key-attribution' },
  provenanceClass: 'EXECUTED BY ZAMBO',
  inputs: { receipt: 'aer1-05-target' },
  outputs: { deliverable: 'verified:aer1-05-target', outcome: 'verified' },
});

const doc = {
  format: 'svaer1-aer1-interop/1',
  svaStandardVersion: '1.4.0',
  aer1Reference: {
    draft: 'draft-zambo-aer1-26',
    kitVersion: '1.6.1',
    corpusUrl: 'https://zambo.dev/aer1/corpus.json',
    evaluatedSetDigest: 'sha256:4ea44dc07125a6f9b7fa472450a30fb56265771cfe87b1772a02b03d1fc166f2',
    bound04VectorSha256: '51499b6a7633af52657881ee228ba7dadd77d58fb53dd2924c5f9fe3f05da3e4',
  },
  keys: { KEY_A: KEY_A.pubHex, KEY_B: KEY_B.pubHex },
  cases: [
    {
      id: 'interop-01',
      origin: 'svaer-04',
      description: 'Valid receipt with clock.status=unattested under KEY_A; AER-1 core passes with clockAttestation=absent and issuerKeyBinding=absent',
      svaer1: v01Sva,
      aer1: v01Aer,
      expected: {
        svaer1: { ok: true, outcome: 'verified', deliverable: 'verified', clock: 'unattested', keyBinding: 'verified' },
        aer1: { ok: true, outcome: 'verified', clockAttestation: 'absent', issuerKeyBinding: 'absent' },
      },
    },
    {
      id: 'interop-02',
      origin: 'svaer-05',
      description: 'Valid receipt with clock.status=drift under secondary key KEY_B; AER-1 core passes with clockAttestation=absent and issuerKeyBinding=absent',
      svaer1: v02Sva,
      aer1: v02Aer,
      expected: {
        svaer1: { ok: true, outcome: 'verified', deliverable: 'verified', clock: 'drift', keyBinding: 'verified' },
        aer1: { ok: true, outcome: 'verified', clockAttestation: 'absent', issuerKeyBinding: 'absent' },
      },
    },
    {
      id: 'interop-03',
      origin: 'svaer-05-key-swap',
      description: 'Key-binding negative control: swapping agency.publicKey (KEY_B -> KEY_A) fails SVA-ER/1 closed; tampering created_at in AER-1 v0.4 fails metadata_hash',
      svaer1: v03Sva,
      aer1: v02Aer,
      aer1MetadataTamper: v03AerTampered,
      expected: {
        svaer1: { ok: false, outcome: 'verification_failed', deliverable: 'not_checked', clock: 'drift', keyBinding: 'verification_failed' },
        aer1: { ok: true, outcome: 'verified', clockAttestation: 'absent', issuerKeyBinding: 'absent' },
        aer1MetadataTamper: { ok: false, outcome: 'verification_failed' },
      },
    },
    {
      id: 'interop-04',
      origin: 'aer1:base/test-vectors/valid/bound-04.json',
      description: 'AER-1 kit 1.6.1 valid/bound-04.json (get_weather Austin) expressed in SVA-ER/1 with attested clock and KEY_A Ed25519 binding',
      svaer1: v04Sva,
      aer1: bound04Aer,
      expected: {
        svaer1: { ok: true, outcome: 'verified', deliverable: 'verified', clock: 'attested', keyBinding: 'verified' },
        aer1: { ok: true, outcome: 'verified', clockAttestation: 'absent', issuerKeyBinding: 'absent' },
      },
    },
    {
      id: 'interop-05',
      origin: 'fmp1-offline-no-rtc',
      description: 'Real-world store-and-forward case: FMP/1 Raspberry Pi mesh node without RTC (clock_trusted=false) delivers custodied message after partition',
      svaer1: v05Sva,
      aer1: v05Aer,
      expected: {
        svaer1: { ok: true, outcome: 'verified', deliverable: 'verified', clock: 'unattested', keyBinding: 'verified' },
        aer1: { ok: true, outcome: 'verified', clockAttestation: 'absent', issuerKeyBinding: 'absent' },
      },
    },
    {
      id: 'interop-06',
      origin: 'aer1:aer-04',
      description: 'AER-1-side authoring of aer-04: a handover.wrap execution recorded on a host with no trusted clock; the SVA-ER/1 twin declares clock.status=unattested under KEY_A, the AER-1 record verifies keylessly with clockAttestation=absent and issuerKeyBinding=absent',
      svaer1: v06Sva,
      aer1: v06Aer,
      expected: {
        svaer1: { ok: true, outcome: 'verified', deliverable: 'verified', clock: 'unattested', keyBinding: 'verified' },
        aer1: { ok: true, outcome: 'verified', clockAttestation: 'absent', issuerKeyBinding: 'absent' },
      },
    },
    {
      id: 'interop-07',
      origin: 'aer1:aer-05',
      description: 'AER-1-side authoring of aer-05: a receipt.verify execution under a drifted clock; the SVA-ER/1 twin declares clock.status=drift and verifies under the second key KEY_B, the AER-1 record names no key (issuerKeyBinding=absent) and verifies by recompute; attribution is the separate AER-1 id-binding layer question, not the core record',
      svaer1: v07Sva,
      aer1: v07Aer,
      expected: {
        svaer1: { ok: true, outcome: 'verified', deliverable: 'verified', clock: 'drift', keyBinding: 'verified' },
        aer1: { ok: true, outcome: 'verified', clockAttestation: 'absent', issuerKeyBinding: 'absent' },
      },
    },
  ],
};

fs.writeFileSync(OUT, JSON.stringify(doc, null, 2) + '\n');
console.log(`Generated ${doc.cases.length} joint AER-1 <-> SVA-ER/1 interop cases -> ${OUT}`);
