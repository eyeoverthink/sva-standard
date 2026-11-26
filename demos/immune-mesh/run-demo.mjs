#!/usr/bin/env node
// Stage 5 Standalone Zero-Dependency Demo: Cross-Agency Immune System (vsc-revoke/1)
// Spins up 4 real local HTTP agencies (A, B, C, D on 127.0.0.1 ephemeral ports) with:
//   - Real Ed25519 keypairs & JCS-signed vsc/1 capsules + vsc-revoke/1 tombstones
//   - Local fuel-metered WASM counterexample reproduction (zero-rumor containment)
//   - 1-hop TTL-clamped gossip (A -> B -> C), re-import hash quarantine, Byzantine auto-demotion (D -> trusted->known)
//   - Outbound Privacy Membrane guard blocking raw PII before any byte hits the socket
// Runs in < 1 second, 0 GPU, 0 npm installs.

import crypto from 'node:crypto';
import http from 'node:http';
import { canonical, runWasmFuelMetered } from '../../conformance/v1/runners/node-verify.mjs';
import { detect } from '../../packages/privacy-membrane/index.js';

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

function makeKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pubHex = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');
  return {
    pubHex,
    sign: (str) => crypto.sign(null, Buffer.from(str, 'utf8'), privateKey).toString('hex'),
  };
}

function ed25519Verify(pubHex, msg, sigHex) {
  try {
    const key = crypto.createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(pubHex, 'hex').toString('base64url') },
      format: 'jwk',
    });
    return crypto.verify(null, Buffer.from(msg, 'utf8'), key, Buffer.from(sigHex, 'hex'));
  } catch { return false; }
}

// WASM encoder helpers (i32 compute)
function uleb(n) { const o = []; do { let b = n & 0x7f; n >>>= 7; if (n) b |= 0x80; o.push(b); } while (n); return o; }
function sleb(n) { const o = []; let m = true; while (m) { let b = n & 0x7f; n >>= 7; if ((n === 0 && !(b & 0x40)) || (n === -1 && (b & 0x40))) m = false; else b |= 0x80; o.push(b); } return o; }
const sec = (id, p) => [id, ...uleb(p.length), ...p];
function wasmI32(paramCount, ops) {
  const body = [0, ...ops, 0x0b];
  return Buffer.from([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    ...sec(1, [1, 0x60, ...uleb(paramCount), ...Array(paramCount).fill(0x7f), 1, 0x7f]),
    ...sec(3, [1, 0]),
    ...sec(7, [1, 4, 0x6d, 0x61, 0x69, 0x6e, 0x00, 0]),
    ...sec(10, [1, ...uleb(body.length), ...body]),
  ]);
}

function makeCapsule(name, wasmBytes, key, tests) {
  const unsigned = {
    spec: 'vsc/1',
    name,
    version: '1.0.0',
    runtime: 'wasm-core-1',
    encoding: 'base64',
    code: wasmBytes.toString('base64'),
    codeSha256: sha256(wasmBytes),
    capabilities: [],
    tests,
    signer: key.pubHex,
  };
  return { ...unsigned, sig: key.sign(canonical(unsigned)) };
}

function makeRevocation({ targetCodeSha256, kind, counterexample, ttl = 1, note = '' }, key) {
  const unsigned = {
    spec: 'vsc-revoke/1',
    targetCodeSha256,
    kind,
    counterexample,
    ttl,
    ...(note ? { note } : {}),
    issuedAt: new Date().toISOString(),
    signer: key.pubHex,
  };
  return { ...unsigned, sig: key.sign(canonical(unsigned)) };
}

function postJson(url, payload) {
  return new Promise((resolve, reject) => {
    const body = Buffer.from(JSON.stringify(payload), 'utf8');
    const req = http.request(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': body.length },
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
        catch { resolve({ status: res.statusCode, body: null }); }
      });
    });
    req.on('error', reject);
    req.end(body);
  });
}

class ImmuneAgency {
  constructor(name, falseFlagDemoteAt = 2) {
    this.name = name;
    this.key = makeKeypair();
    this.falseFlagDemoteAt = falseFlagDemoteAt;
    this.peers = new Map(); // pubHex -> { name, url, trust: 'trusted'|'known', repConfirmed, repFalseFlags }
    this.skills = new Map(); // codeSha256 -> { capsule, status: 'active'|'quarantined' }
    this.quarantinedHashes = new Set();
    this.seenAdvisories = new Set();
    this.ledger = [];
    this.server = null;
    this.url = null;
  }

  async start() {
    this.server = http.createServer(async (req, res) => {
      if (req.method === 'POST' && req.url === '/mesh/revoke') {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        const msg = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        const out = await this.handleRevocation(msg);
        res.writeHead(out.status || 200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(out));
        return;
      }
      res.writeHead(404).end();
    });
    await new Promise((r) => this.server.listen(0, '127.0.0.1', r));
    this.url = `http://127.0.0.1:${this.server.address().port}`;
  }

  async stop() {
    if (this.server) await new Promise((r) => this.server.close(r));
  }

  addPeer(agency, trust = 'trusted') {
    this.peers.set(agency.key.pubHex, {
      name: agency.name,
      url: agency.url,
      trust,
      repConfirmed: 0,
      repFalseFlags: 0,
    });
  }

  importSkill(capsule) {
    if (!capsule?.sig || !capsule?.signer) return { imported: false, reason: 'missing signature (fail-closed)' };
    const { sig, ...unsigned } = capsule;
    if (!ed25519Verify(capsule.signer, canonical(unsigned), sig)) return { imported: false, reason: 'invalid signature' };
    if (this.quarantinedHashes.has(capsule.codeSha256)) {
      return { imported: false, reason: `blocked: ${capsule.name} (${capsule.codeSha256.slice(0, 12)}) quarantined by confirmed immune advisory` };
    }
    this.skills.set(capsule.codeSha256, { capsule, status: 'active' });
    return { imported: true };
  }

  async emitRevocation(rev, targetPeers = null) {
    // Outbound Privacy Membrane guard: never broadcast raw PII/secrets in counterexamples or notes
    const scanHits = detect(canonical(rev));
    if (scanHits.length > 0) {
      this.ledger.push({ kind: 'immune.advisory_blocked', types: [...new Set(scanHits.map((h) => h.type))] });
      return { blocked: true, reason: 'privacy_membrane_egress_block', types: [...new Set(scanHits.map((h) => h.type))] };
    }
    const recipients = targetPeers
      ? targetPeers.map((a) => this.peers.get(a.key.pubHex)).filter(Boolean)
      : [...this.peers.values()].filter((p) => p.trust === 'trusted');
    const results = [];
    for (const peer of recipients) {
      const r = await postJson(`${peer.url}/mesh/revoke`, rev);
      results.push({ peer: peer.name, status: r.status, reply: r.body });
    }
    return { blocked: false, sent: results.length, results };
  }

  async handleRevocation(rev) {
    const peer = this.peers.get(rev?.signer);
    if (!peer || peer.trust !== 'trusted') {
      return { status: 403, ok: false, verdict: 'rejected_untrusted_peer' };
    }
    const { sig, ...unsigned } = rev;
    if (!sig || !ed25519Verify(rev.signer, canonical(unsigned), sig)) {
      return { status: 400, ok: false, verdict: 'invalid_signature' };
    }
    const advKey = sha256(canonical({ target: rev.targetCodeSha256, kind: rev.kind, input: rev.counterexample?.input }));
    if (this.seenAdvisories.has(advKey)) {
      return { status: 200, ok: true, verdict: 'duplicate_ignored' };
    }
    this.seenAdvisories.add(advKey);

    const entry = this.skills.get(rev.targetCodeSha256);
    if (!entry) return { status: 200, ok: true, verdict: 'skill_not_installed' };
    if (entry.status === 'quarantined') return { status: 200, ok: true, verdict: 'already_quarantined' };

    // Zero-rumor rule: execute counterexample locally in fuel-metered WASM VM
    const bytes = Buffer.from(entry.capsule.code, 'base64');
    const ce = rev.counterexample || {};
    const execRes = runWasmFuelMetered(bytes, ce.input || [], 1000);

    let confirmed = false;
    if (rev.kind === 'crash') {
      confirmed = Boolean(execRes.trap && execRes.trap !== 'fuel_exhausted');
    } else if (rev.kind === 'wrong_output') {
      confirmed = !execRes.trap && execRes.value === ce.observed && execRes.value !== ce.expected;
    }

    if (confirmed) {
      entry.status = 'quarantined';
      this.quarantinedHashes.add(rev.targetCodeSha256);
      peer.repConfirmed += 1;
      this.ledger.push({ kind: 'immune.quarantine', skill: entry.capsule.name, by: peer.name, kindFault: rev.kind });

      // 1-hop TTL-clamped relay to other trusted peers (re-signed by this agency)
      let relayed = 0;
      const nextTtl = Math.min(3, Number(rev.ttl || 0)) - 1;
      if (nextTtl >= 0) {
        const relayRev = makeRevocation({
          targetCodeSha256: rev.targetCodeSha256,
          kind: rev.kind,
          counterexample: rev.counterexample,
          ttl: nextTtl,
        }, this.key);
        for (const [pk, p] of this.peers.entries()) {
          if (pk === rev.signer || p.trust !== 'trusted') continue;
          await postJson(`${p.url}/mesh/revoke`, relayRev);
          relayed += 1;
        }
      }
      return { status: 200, ok: true, verdict: 'confirmed', skill: entry.capsule.name, relayed, repConfirmed: peer.repConfirmed };
    }

    // False flag: skill stayed healthy under the counterexample -> penalize sender reputation
    peer.repFalseFlags += 1;
    let demoted = false;
    if (peer.repFalseFlags >= this.falseFlagDemoteAt) {
      peer.trust = 'known';
      demoted = true;
    }
    this.ledger.push({ kind: 'immune.false_flag', skill: entry.capsule.name, sender: peer.name, demoted });
    return { status: 200, ok: true, verdict: 'false_flag', skill: entry.capsule.name, demoted, repFalseFlags: peer.repFalseFlags };
  }
}

export async function runImmuneMeshDemo() {
  const t0 = performance.now();
  const [A, B, C, D] = ['A', 'B', 'C', 'D'].map((n) => new ImmuneAgency(n));
  await Promise.all([A, B, C, D].map((a) => a.start()));

  try {
    // Topology: A <-> B <-> C (1-hop chain for gossip), and D -> B, C (Byzantine peer)
    A.addPeer(B); B.addPeer(A);
    B.addPeer(C); C.addPeer(B);
    D.addPeer(B); D.addPeer(C);
    B.addPeer(D); C.addPeer(D);

    // 3 real compiled WASM Core 1.0 capsules
    const capCrash = makeCapsule(
      'wasm_tax_split_unsafe',
      wasmI32(3, [0x20, 0, 0x41, ...sleb(100), 0x20, 1, 0x6a, 0x6c, 0x41, ...sleb(100), 0x6d, 0x20, 2, 0x6d]),
      A.key,
      [{ input: [10000, 8, 4], output: 2700 }],
    );
    const capBuggy = makeCapsule(
      'wasm_buggy_discount',
      wasmI32(2, [0x20, 0, 0x20, 1, 0x6b]), // returns price - pct instead of percentage discount
      A.key,
      [{ input: [100, 0], output: 100 }],
    );
    const capHealthy = makeCapsule(
      'wasm_discount_cents',
      wasmI32(3, [
        0x20, 0, 0x41, ...sleb(100), 0x20, 1, 0x6b, 0x6c, 0x41, ...sleb(100), 0x6d,
        0x41, ...sleb(100), 0x20, 2, 0x6b, 0x6c, 0x41, ...sleb(100), 0x6d,
      ]),
      A.key,
      [{ input: [10000, 20, 10], output: 7200 }],
    );

    for (const ag of [A, B, C, D]) {
      ag.importSkill(capCrash);
      ag.importSkill(capBuggy);
      ag.importSkill(capHealthy);
    }

    // Scenario 1: Crash containment A -> B -> C (1-hop gossip, 0 GPU)
    const t1 = performance.now();
    const revCrash = makeRevocation({
      targetCodeSha256: capCrash.codeSha256,
      kind: 'crash',
      counterexample: { input: [10000, 8, 0] },
      ttl: 1,
    }, A.key);
    const s1 = await A.emitRevocation(revCrash, [B]);
    const s1Ms = Math.round((performance.now() - t1) * 100) / 100;

    // Scenario 2: Wrong-output containment + re-import quarantine block
    const t2 = performance.now();
    const revBuggy = makeRevocation({
      targetCodeSha256: capBuggy.codeSha256,
      kind: 'wrong_output',
      counterexample: { input: [10000, 20], expected: 8000, observed: 9980 },
      ttl: 1,
    }, A.key);
    await A.emitRevocation(revBuggy, [B]);
    const reimportB = B.importSkill(capBuggy);
    const reimportC = C.importSkill(capBuggy);
    const s2Ms = Math.round((performance.now() - t2) * 100) / 100;

    // Scenario 3: Byzantine peer D sends 2 false flags against healthy skill -> auto-demoted trusted -> known, 3rd rejected HTTP 403
    const t3 = performance.now();
    const fake1 = makeRevocation({
      targetCodeSha256: capHealthy.codeSha256,
      kind: 'wrong_output',
      counterexample: { input: [10000, 20, 10], expected: 9999, observed: 1111 },
    }, D.key);
    const fake2 = makeRevocation({
      targetCodeSha256: capHealthy.codeSha256,
      kind: 'crash',
      counterexample: { input: [24000, 25, 10] },
    }, D.key);
    const fake3 = makeRevocation({
      targetCodeSha256: capHealthy.codeSha256,
      kind: 'crash',
      counterexample: { input: [5000, 10, 5] },
    }, D.key);
    await D.emitRevocation(fake1, [B, C]);
    await D.emitRevocation(fake2, [B, C]);
    const afterDemote = await D.emitRevocation(fake3, [B, C]);
    const s3Ms = Math.round((performance.now() - t3) * 100) / 100;

    // Scenario 4: Outbound Privacy Membrane blocks advisory containing raw PII + fail-closed unsigned skill check
    const piiRev = makeRevocation({
      targetCodeSha256: capHealthy.codeSha256,
      kind: 'crash',
      counterexample: { input: [1, 2, 3] },
      note: 'Patient SSN 123-45-6789 caused fault',
    }, A.key);
    const piiBlocked = await A.emitRevocation(piiRev, [B]);
    const unsignedImport = B.importSkill({ ...capHealthy, sig: null });

    return {
      ok: (
        B.skills.get(capCrash.codeSha256).status === 'quarantined' &&
        C.skills.get(capCrash.codeSha256).status === 'quarantined' &&
        B.skills.get(capBuggy.codeSha256).status === 'quarantined' &&
        C.skills.get(capBuggy.codeSha256).status === 'quarantined' &&
        reimportB.imported === false &&
        reimportC.imported === false &&
        B.skills.get(capHealthy.codeSha256).status === 'active' &&
        C.skills.get(capHealthy.codeSha256).status === 'active' &&
        B.peers.get(D.key.pubHex).trust === 'known' &&
        C.peers.get(D.key.pubHex).trust === 'known' &&
        afterDemote.results.every((r) => r.status === 403) &&
        piiBlocked.blocked === true &&
        unsignedImport.imported === false
      ),
      gpuCalls: 0,
      totalMs: Math.round((performance.now() - t0) * 100) / 100,
      scenarios: {
        crashContainmentGossip: {
          ms: s1Ms,
          bStatus: B.skills.get(capCrash.codeSha256).status,
          cStatus: C.skills.get(capCrash.codeSha256).status,
          bRepConfirmedForA: B.peers.get(A.key.pubHex).repConfirmed,
          cRepConfirmedForB: C.peers.get(B.key.pubHex).repConfirmed,
          relayedByB: s1.results[0]?.reply?.relayed ?? 0,
        },
        wrongOutputAndReimportBlock: {
          ms: s2Ms,
          bStatus: B.skills.get(capBuggy.codeSha256).status,
          cStatus: C.skills.get(capBuggy.codeSha256).status,
          reimportBlockedB: !reimportB.imported,
          reimportBlockedC: !reimportC.imported,
        },
        byzantineAutoDemotion: {
          ms: s3Ms,
          falseQuarantines: 0,
          healthyStatusB: B.skills.get(capHealthy.codeSha256).status,
          healthyStatusC: C.skills.get(capHealthy.codeSha256).status,
          peerDOnB: { trust: B.peers.get(D.key.pubHex).trust, repFalseFlags: B.peers.get(D.key.pubHex).repFalseFlags },
          peerDOnC: { trust: C.peers.get(D.key.pubHex).trust, repFalseFlags: C.peers.get(D.key.pubHex).repFalseFlags },
          postDemotionStatuses: afterDemote.results.map((r) => r.status),
        },
        securityAndPrivacyNegativeControls: {
          piiAdvisoryBlocked: piiBlocked.blocked,
          piiTypesCaught: piiBlocked.types,
          unsignedCapsuleRejected: !unsignedImport.imported,
        },
      },
    };
  } finally {
    await Promise.all([A, B, C, D].map((a) => a.stop()));
  }
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/'))) {
  const res = await runImmuneMeshDemo();
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.ok ? 0 : 1);
}
