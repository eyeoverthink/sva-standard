#!/usr/bin/env node
// Joint Interop Verifier: evaluates every case in conformance/interop/aer1-svaer1/vectors.json
// against BOTH SVA-ER/1 (evaluateSvaEr1) AND AER-1 v0.4 (draft-zambo-aer1-26 core + Section 3.1 metadata_hash).
// Zero external dependencies.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateSvaEr1 } from '../../v1/runners/node-verify.mjs';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_VEC = path.join(DIR, 'vectors.json');

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const NIL_UUID = '00000000-0000-0000-0000-000000000000';
const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const PROV_RE = /^(EXECUTED BY [A-Z0-9][A-Z0-9 ._-]*|OBSERVED VIA GATEWAY|LOGGED BY AGENT)$/;
const STRICT_B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const RFC3339_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-](\d{2}):(\d{2}))$/;

const sha256 = (b) => crypto.createHash('sha256').update(b).digest('hex');

function validRfc3339(s) {
  if (typeof s !== 'string') return false;
  const m = RFC3339_RE.exec(s);
  if (!m) return false;
  const y = +m[1], mo = +m[2], d = +m[3], hh = +m[4], mm = +m[5], ss = +m[6];
  if (y < 1 || mo < 1 || mo > 12 || hh > 23 || mm > 59 || ss > 59) return false;
  const leap = (y % 4 === 0 && y % 100 !== 0) || (y % 400 === 0);
  const maxD = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][mo - 1];
  if (d < 1 || d > maxD) return false;
  if (m[7] !== 'Z' && (+m[8] > 23 || +m[9] > 59)) return false;
  return true;
}

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

// Evaluates an AER-1 v0.4 receipt per draft-zambo-aer1-26 (core + version/provenance binding + Section 3.1 metadata_hash).
// Explicitly reports clockAttestation="absent" and issuerKeyBinding="absent" because core AER-1 does not carry them in-band.
export function evaluateAer1V04(r) {
  const fail = (reason) => ({
    ok: false,
    outcome: 'verification_failed',
    clockAttestation: 'absent',
    issuerKeyBinding: 'absent',
    reason,
  });
  if (!r || typeof r !== 'object' || Array.isArray(r)) return fail('not an object');
  for (const k of ['id', 'receipt_schema_version', 'created_at', 'tool', 'provenance_class', 'canonical_bytes', 'output_hash', 'verification_status', 'metadata_hash']) {
    if (!(k in r)) return fail(`missing ${k}`);
  }
  if (typeof r.id !== 'string' || !UUID_RE.test(r.id) || r.id === NIL_UUID) return fail('invalid id');
  if (r.receipt_schema_version !== '0.4') return fail('expected schema version 0.4');
  if (!validRfc3339(r.created_at)) return fail('invalid created_at');
  if (!r.tool || typeof r.tool !== 'object' || !['name', 'version', 'scope'].every((k) => typeof r.tool[k] === 'string' && r.tool[k].length > 0)) {
    return fail('invalid tool');
  }
  if (typeof r.provenance_class !== 'string' || !PROV_RE.test(r.provenance_class)) return fail('invalid provenance_class');
  if (!['verified', 'unverified', 'failed'].includes(r.verification_status)) return fail('invalid verification_status');
  if (typeof r.canonical_bytes !== 'string' || !STRICT_B64.test(r.canonical_bytes)) return fail('invalid canonical_bytes');
  if (typeof r.output_hash !== 'string' || !HASH_RE.test(r.output_hash)) return fail('invalid output_hash');
  if (typeof r.metadata_hash !== 'string' || !HASH_RE.test(r.metadata_hash)) return fail('invalid metadata_hash');

  const rawBytes = Buffer.from(r.canonical_bytes, 'base64');
  if ('sha256:' + sha256(rawBytes) !== r.output_hash) return fail('output_hash mismatch');

  let payload;
  try { payload = JSON.parse(rawBytes.toString('utf8')); } catch { return fail('canonical_bytes not UTF-8 JSON'); }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return fail('payload not object');
  if (payload.receipt_schema_version !== r.receipt_schema_version) return fail('version agreement mismatch');
  if (payload.issuer_claims?.provenance_class !== r.provenance_class) return fail('provenance binding mismatch');

  const metaBlock = {
    created_at: r.created_at,
    id: r.id,
    output_hash: r.output_hash,
    provenance_class: r.provenance_class,
    receipt_schema_version: r.receipt_schema_version,
    tool: { name: r.tool.name, scope: r.tool.scope, version: r.tool.version },
  };
  const expectedMeta = 'sha256:' + sha256(Buffer.from(aer1Canonical(metaBlock), 'utf8'));
  if (expectedMeta !== r.metadata_hash) return fail('metadata_hash mismatch');

  return {
    ok: true,
    outcome: 'verified',
    clockAttestation: 'absent',
    issuerKeyBinding: 'absent',
  };
}

export function runInteropVerification(vecPath = DEFAULT_VEC) {
  const doc = JSON.parse(fs.readFileSync(vecPath, 'utf8'));
  const results = [];
  const failures = [];

  for (const c of doc.cases) {
    const svaRaw = evaluateSvaEr1(c.svaer1);
    const sva = { ...svaRaw, keyBinding: svaRaw.ok ? 'verified' : 'verification_failed' };
    const aer = evaluateAer1V04(c.aer1);
    const aerTamper = c.aer1MetadataTamper ? evaluateAer1V04(c.aer1MetadataTamper) : null;

    const checks = [];
    for (const [k, v] of Object.entries(c.expected.svaer1)) {
      if (sva[k] !== v) checks.push(`svaer1.${k}: expected ${v}, got ${sva[k]}`);
    }
    for (const [k, v] of Object.entries(c.expected.aer1)) {
      if (aer[k] !== v) checks.push(`aer1.${k}: expected ${v}, got ${aer[k]}`);
    }
    if (c.expected.aer1MetadataTamper) {
      for (const [k, v] of Object.entries(c.expected.aer1MetadataTamper)) {
        if (aerTamper[k] !== v) checks.push(`aer1MetadataTamper.${k}: expected ${v}, got ${aerTamper[k]}`);
      }
    }

    const passed = checks.length === 0;
    results.push({ id: c.id, origin: c.origin, passed, svaer1: sva, aer1: aer, ...(aerTamper ? { aer1MetadataTamper: aerTamper } : {}) });
    if (!passed) failures.push({ id: c.id, checks });
  }

  return {
    format: doc.format,
    aer1KitVersion: doc.aer1Reference.kitVersion,
    aer1EvaluatedSetDigest: doc.aer1Reference.evaluatedSetDigest,
    total: doc.cases.length,
    passed: doc.cases.length - failures.length,
    failed: failures.length,
    failures,
    results,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const res = runInteropVerification(process.argv[2]);
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.failed === 0 ? 0 : 1);
}
