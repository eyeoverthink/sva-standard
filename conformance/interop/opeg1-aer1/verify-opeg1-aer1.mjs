#!/usr/bin/env node
// OPEG/1 + AER-1 wiring runner: evaluates an OPEG/1 S4_COMMIT envelope whose
// receiptFormat is "aer-1" against specs/OPEG-1.md Section 4 (main HEAD).
//
// OPEG/1 ships no packaged gate function for the "aer-1" profile, so this
// runner composes the gate from the spec text:
//   - Rules 1-4 (envelope + sanitizer binding) are checked here directly.
//   - Rule 5's "aer-1" leg delegates to evaluateAer1V04, the AER-1 v0.4
//     evaluator already in this repo at ../aer1-svaer1/verify-interop.mjs
//     (draft-zambo-aer1-26 core + issuer_claims binding + Section 3.1
//     metadata_hash), plus the rule 5.2 outputs-digest binding.
//   - Rule 5.3: the verdict preserves AER-1's explicit absent readings
//     (clockAttestation: "absent", issuerKeyBinding: "absent").
//
// Usage: node verify-opeg1-aer1.mjs [envelope.json]
// Exit code 0 when the gate passes, 1 when it stays blocked.
// Zero external dependencies.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { evaluateAer1V04 } from '../aer1-svaer1/verify-interop.mjs';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const sha256hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// RFC 8785 (JCS) canonicalization. Object keys sort by UTF-16 code units
// (the JavaScript default), strings and numbers serialize per JSON.stringify,
// which is the ECMAScript number-to-string JCS mandates. Inputs JCS cannot
// canonicalize are rejected instead of serialized leniently: non-finite
// numbers (JSON.stringify would emit null) and strings or keys containing
// lone UTF-16 surrogates (not valid Unicode, so not I-JSON).
function assertWellFormed(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) throw new Error('lone surrogate in JCS string input');
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new Error('lone surrogate in JCS string input');
    }
  }
}
function jcs(val) {
  if (val === null) return 'null';
  if (Array.isArray(val)) return '[' + val.map(jcs).join(',') + ']';
  if (typeof val === 'object') {
    const keys = Object.keys(val).sort();
    return '{' + keys.map((k) => { assertWellFormed(k); return JSON.stringify(k) + ':' + jcs(val[k]); }).join(',') + '}';
  }
  if (typeof val === 'number') {
    if (!Number.isFinite(val)) throw new Error('non-finite number in JCS input');
    return JSON.stringify(val);
  }
  if (typeof val === 'string') { assertWellFormed(val); return JSON.stringify(val); }
  if (typeof val === 'boolean') return JSON.stringify(val);
  throw new Error('unsupported type in JCS input: ' + typeof val);
}

export function evaluateOpeg1Aer1(envelope) {
  const checks = [];
  const check = (rule, ok, detail) => checks.push({ rule, ok, ...(detail ? { detail } : {}) });

  // Rule 1: spec and state.
  check('1 spec/state', envelope?.spec === 'opeg/1' && envelope?.state === 'S4_COMMIT',
    `spec=${JSON.stringify(envelope?.spec)}, state=${JSON.stringify(envelope?.state)}`);
  // Rule 2: mode.
  check('2 mode', envelope?.mode === 'EXECUTE_AND_RECEIVE', `mode=${JSON.stringify(envelope?.mode)}`);
  // Rule 3: source priority begins with runtime_receipt.
  check('3 sourcePriority', Array.isArray(envelope?.sourcePriority) && envelope.sourcePriority[0] === 'runtime_receipt',
    `sourcePriority[0]=${JSON.stringify(envelope?.sourcePriority?.[0])}`);
  // Rule 4: sanitizer status, non-null object rSan, digest binding.
  // A rSan that JCS cannot canonicalize fails the check, never throws.
  const san = envelope?.sanitizer;
  const rSanOk = !!san && typeof san === 'object' && san.rSan !== null && typeof san.rSan === 'object' && !Array.isArray(san.rSan);
  let rSanDigest = null;
  let rSanError = '';
  if (rSanOk) {
    try { rSanDigest = sha256hex(Buffer.from(jcs(san.rSan), 'utf8')); } catch (e) { rSanError = e.message; }
  }
  check('4 sanitizer', !!san && san.status === 'SUCCESS' && rSanOk && rSanDigest !== null && san.rSanSha256 === rSanDigest,
    rSanError ? `rSan not canonicalizable: ${rSanError}` : rSanOk ? `SHA-256(JCS(rSan))=${rSanDigest}, envelope rSanSha256=${san.rSanSha256}` : 'rSan missing or not an object');

  // Rule 5, "aer-1" leg.
  const fmt = envelope?.receiptFormat ?? 'sva-er/1';
  let aer = null;
  let bindingOk = false;
  let bindingDetail = '';
  if (fmt !== 'aer-1') {
    check('5 receiptFormat', false, `this runner covers the "aer-1" profile only, got ${JSON.stringify(fmt)}`);
  } else {
    aer = evaluateAer1V04(envelope.receipt);
    // The gate decodes canonical_bytes strictly, once: the bytes must be
    // valid UTF-8 JSON (a lenient decode would silently replace malformed
    // bytes and evaluate an altered payload). The strictly parsed payload
    // feeds both the 5.1 acceptance and the 5.2 binding.
    let payload = null;
    let bytesError = '';
    try {
      const raw = Buffer.from(envelope.receipt.canonical_bytes, 'base64');
      payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    } catch (e) {
      bytesError = e.message;
    }
    // Rule 5.1: the delegated evaluator checks structure, hashes, and
    // bindings, but accepts any well-formed verification_status. The gate
    // additionally requires the receipt's own status to be "verified":
    // a receipt reporting "failed" or "unverified" does not unlock S4_COMMIT.
    const statusOk = envelope.receipt?.verification_status === 'verified';
    const leg51 = aer.ok && statusOk && payload !== null;
    check('5.1 aer-1 receipt (evaluateAer1V04)', leg51,
      !aer.ok ? `reason=${aer.reason}`
        : !statusOk ? `verification_status=${JSON.stringify(envelope.receipt?.verification_status)}, gate requires "verified"`
        : payload === null ? `canonical_bytes not strict UTF-8 JSON: ${bytesError}`
        : `outcome=${aer.outcome}`);
    // Rule 5.2: payload.outputs binds sanitizer.rSanSha256, direct or explicit.
    if (payload === null || typeof payload !== 'object') {
      bindingDetail = 'canonical_bytes payload unreadable: ' + (bytesError || 'payload not an object');
    } else {
      try {
        const direct = sha256hex(Buffer.from(jcs(payload.outputs), 'utf8'));
        const explicit = payload.outputs?.rSanSha256;
        const directOk = direct === san?.rSanSha256;
        const explicitOk = explicit === san?.rSanSha256 || explicit === 'sha256:' + san?.rSanSha256;
        bindingOk = directOk || explicitOk;
        bindingDetail = directOk
          ? `direct payload match: SHA-256(JCS(payload.outputs))=${direct}`
          : explicitOk
            ? `explicit digest field: payload.outputs.rSanSha256=${explicit}`
            : `no binding: SHA-256(JCS(payload.outputs))=${direct}, envelope rSanSha256=${san?.rSanSha256}`;
      } catch (e) {
        bindingDetail = 'canonical_bytes payload unreadable: ' + e.message;
      }
    }
    check('5.2 outputs binding', bindingOk, bindingDetail);
  }

  const pass = checks.every((c) => c.ok);
  return {
    spec: 'opeg/1',
    state: 'S4_COMMIT',
    receiptFormat: fmt,
    gate: pass ? 'pass' : 'blocked',
    checks,
    // Rule 5.3: preserve AER-1's explicit absent readings, never collapse to a boolean.
    receiptOutcome: aer
      ? { outcome: aer.outcome, clockAttestation: aer.clockAttestation, issuerKeyBinding: aer.issuerKeyBinding }
      : null,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const envPath = process.argv[2] ? path.resolve(process.argv[2]) : path.join(DIR, 'envelope.json');
  const envelope = JSON.parse(fs.readFileSync(envPath, 'utf8'));
  const verdict = evaluateOpeg1Aer1(envelope);
  console.log(JSON.stringify(verdict, null, 2));
  process.exit(verdict.gate === 'pass' ? 0 : 1);
}
