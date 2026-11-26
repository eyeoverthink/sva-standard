#!/usr/bin/env node
// Reference Verifier #2: W3C Browser WebCrypto (globalThis.crypto.subtle — ZERO node:crypto imports!).
// The exported verifyVector() function is 100% browser-native and runs identically in browsers and Node 22+.

const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const HEX64 = /^[0-9a-f]{64}$/i;
const HEX128 = /^[0-9a-f]{128}$/i;
const HEX16 = /^[0-9a-f]{16}$/;
const enc = new TextEncoder();

const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (h) => new Uint8Array(String(h).match(/.{1,2}/g)?.map((x) => parseInt(x, 16)) || []);
const concatBytes = (...parts) => {
  const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};
const decodeBase64 = (b64) => {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};

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

async function sha256Bytes(bytes) {
  return toHex(await globalThis.crypto.subtle.digest('SHA-256', bytes));
}
async function sha256Text(text) {
  return sha256Bytes(enc.encode(text));
}
async function merkleLeaf(h) {
  return sha256Bytes(concatBytes(new Uint8Array([0x00]), enc.encode(String(h))));
}
async function merkleNode(l, r) {
  return sha256Bytes(concatBytes(new Uint8Array([0x01]), enc.encode(String(l)), enc.encode(String(r))));
}

async function ed25519Verify(pubHex, msg, sigHex) {
  try {
    if (!HEX64.test(String(pubHex || '')) || !HEX128.test(String(sigHex || ''))) return false;
    const key = await globalThis.crypto.subtle.importKey('raw', fromHex(pubHex), { name: 'Ed25519' }, false, ['verify']);
    return await globalThis.crypto.subtle.verify({ name: 'Ed25519' }, key, fromHex(sigHex), enc.encode(msg));
  } catch { return false; }
}

async function hmacTag(keyHex, val) {
  const key = await globalThis.crypto.subtle.importKey('raw', enc.encode(keyHex), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await globalThis.crypto.subtle.sign('HMAC', key, enc.encode(String(val).toLowerCase()));
  return toHex(sig).slice(0, 16);
}

function expectedSteps(seq, size) {
  if (!Number.isInteger(seq) || !Number.isInteger(size) || seq < 1 || size < 1 || seq > size) return null;
  const steps = [];
  let idx = seq - 1, len = size;
  while (len > 1) {
    if (idx % 2 === 0 && idx + 1 === len) { idx = Math.floor(idx / 2); len = Math.ceil(len / 2); continue; }
    steps.push(idx % 2 === 1);
    idx = Math.floor(idx / 2);
    len = Math.ceil(len / 2);
  }
  return steps;
}

async function verifyMerkle({ leaf, seq, size, root, path: steps }) {
  if (!HEX64.test(String(leaf || '')) || !HEX64.test(String(root || '')) || !Array.isArray(steps)) return false;
  const exp = expectedSteps(seq, size);
  if (!exp || exp.length !== steps.length) return false;
  let h = await merkleLeaf(leaf);
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    if (!s || !HEX64.test(String(s.hash || '')) || Boolean(s.left) !== exp[i]) return false;
    h = s.left ? await merkleNode(s.hash, h) : await merkleNode(h, s.hash);
  }
  return h === root;
}

async function verifyAer1({ receipt, deliverable }) {
  if (!receipt || receipt.spec !== 'aer/1') return false;
  const pub = receipt.agency?.publicKey;
  const st = receipt.statement;
  if (!HEX64.test(String(pub || '')) || !st || typeof st !== 'object' || Array.isArray(st) || !Array.isArray(receipt.entries)) return false;
  if (st.type !== 'aer.statement' || typeof st.missionId !== 'string' || st.missionId.length === 0) return false;
  if (!HEX64.test(String(st.deliverableSha256 || '')) || !HEX64.test(String(st.merkleRoot || ''))) return false;
  if (st.merkle !== 'rfc6962-sha256' || !Number.isSafeInteger(st.size) || st.size < 1 || !Number.isSafeInteger(st.entries) || st.entries < 1) return false;
  if (!st.clock || typeof st.clock !== 'object' || !['attested', 'drift', 'unattested'].includes(st.clock.status) || typeof st.clock.issuedAt !== 'string' || st.clock.issuedAt.length === 0) return false;
  if (!await ed25519Verify(pub, canonical(st), receipt.statementSig)) return false;
  if (receipt.entries.length !== st.entries) return false;

  const seen = new Set();
  let hasComplete = false;
  for (const e of receipt.entries) {
    if (!e || !Number.isSafeInteger(e.seq) || e.seq < 1 || e.seq > st.size || seen.has(e.seq)) return false;
    seen.add(e.seq);
    const recomputed = await sha256Text(canonical({ seq: e.seq, ts: e.ts, kind: e.kind, actor: e.actor, data: e.data, prev: e.prev }));
    if (recomputed !== e.hash) return false;
    if (e.signer !== pub || !await ed25519Verify(pub, e.hash, e.sig)) return false;
    if (!await verifyMerkle({ leaf: e.hash, seq: e.seq, size: st.size, root: st.merkleRoot, path: e.proof })) return false;
    if (e.data?.id !== st.missionId && e.data?.missionId !== st.missionId) return false;
    if (e.kind === 'mission.complete') {
      if (e.data?.resultHash !== st.deliverableSha256) return false;
      hasComplete = true;
    }
  }
  if (!hasComplete) return false;
  if (deliverable != null && await sha256Text(String(deliverable)) !== st.deliverableSha256) return false;
  return true;
}

const STRICT_B64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

async function verifyVsc1(doc) {
  if (!doc || typeof doc !== 'object') return false;
  if (doc.spec === 'vsc-revoke/1') {
    if (!HEX64.test(String(doc.targetCodeSha256 || ''))) return false;
    if (!['crash', 'wrong_output', 'nondeterministic', 'invariant_violation'].includes(doc.kind)) return false;
    if (!doc.counterexample || typeof doc.counterexample !== 'object' || doc.counterexample.input == null) return false;
    if (!HEX64.test(String(doc.signer || '')) || !HEX128.test(String(doc.sig || ''))) return false;
    const { sig, ...unsigned } = doc;
    return ed25519Verify(doc.signer, canonical(unsigned), sig);
  }
  if (doc.spec !== 'vsc/1') return false;
  if (!/^[a-z][a-z0-9_-]{1,63}$/.test(String(doc.name || ''))) return false;
  if (['__proto__', 'constructor', 'prototype'].includes(doc.name)) return false;
  if (!['wasm-core-1', 'js-pure-es2022'].includes(doc.runtime)) return false;
  if (!Array.isArray(doc.capabilities) || doc.capabilities.length !== 0) return false;
  if (!Array.isArray(doc.tests) || doc.tests.length === 0) return false;
  if (typeof doc.code !== 'string' || !HEX64.test(String(doc.codeSha256 || ''))) return false;
  const expectedEnc = doc.runtime === 'wasm-core-1' ? 'base64' : 'utf8';
  if (doc.encoding !== expectedEnc) return false;
  let codeBytes;
  if (doc.encoding === 'base64') {
    if (!STRICT_B64.test(doc.code)) return false;
    try { codeBytes = decodeBase64(doc.code); } catch { return false; }
  } else {
    codeBytes = enc.encode(doc.code);
  }
  if (await sha256Bytes(codeBytes) !== doc.codeSha256) return false;
  if (doc.runtime === 'wasm-core-1') {
    if (codeBytes.length < 8) return false;
    const magic = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    for (let i = 0; i < 8; i++) if (codeBytes[i] !== magic[i]) return false;
  }
  if (!HEX64.test(String(doc.signer || '')) || !HEX128.test(String(doc.sig || ''))) return false;
  const { sig, ...unsigned } = doc;
  return ed25519Verify(doc.signer, canonical(unsigned), sig);
}

const squeezeDigits = (s) => String(s).replace(/(?<=\d)[\s.\-()]+(?=\d)/g, '');

async function verifyEma1({ attestation: a, outboundPayload, hmacKeyHex, originals }) {
  if (!a || a.spec !== 'ema/1') return false;
  if (!['SEALED_EGRESS', 'ONLY_ON_DEVICE'].includes(a.mode)) return false;
  if (a.audit !== 'clean') return false;
  if (!HEX64.test(String(a.outboundSha256 || '')) || !Number.isSafeInteger(a.egressBytes) || a.egressBytes < 0) return false;
  if (!Array.isArray(a.tags) || !a.withheld || typeof a.withheld !== 'object' || Array.isArray(a.withheld)) return false;
  if (!Number.isSafeInteger(a.totalWithheld) || a.totalWithheld < 0) return false;
  let sum = 0;
  for (const n of Object.values(a.withheld)) {
    if (!Number.isSafeInteger(n) || n < 0) return false;
    sum += n;
  }
  if (sum !== a.totalWithheld || a.tags.length !== a.totalWithheld) return false;
  const tagCounts = Object.create(null);
  for (const t of a.tags) {
    if (!t || typeof t.type !== 'string' || !t.type.length || !HEX16.test(String(t.tag || ''))) return false;
    tagCounts[t.type] = (tagCounts[t.type] || 0) + 1;
  }
  for (const [type, count] of Object.entries(a.withheld)) {
    if ((tagCounts[type] || 0) !== count) return false;
  }
  for (const type of Object.keys(tagCounts)) {
    if (!Object.prototype.hasOwnProperty.call(a.withheld, type)) return false;
  }
  if (a.mode === 'ONLY_ON_DEVICE') {
    if (a.egressBytes !== 0 || a.outboundSha256 !== EMPTY_SHA256) return false;
    if (a.airgap !== undefined && a.airgap !== null) {
      if (typeof a.airgap !== 'object' || Array.isArray(a.airgap) || a.airgap.networkInterfaces !== 0 || a.airgap.verified !== true) return false;
    }
  }
  if (!HEX64.test(String(a.signer || '')) || !HEX128.test(String(a.sig || ''))) return false;
  const { sig, ...unsigned } = a;
  if (!await ed25519Verify(a.signer, canonical(unsigned), sig)) return false;

  if (outboundPayload != null) {
    const bytes = enc.encode(String(outboundPayload));
    if (await sha256Bytes(bytes) !== a.outboundSha256 || bytes.length !== a.egressBytes) return false;
  }
  const origList = Array.isArray(originals) ? originals : [];
  if (origList.length > 0 && outboundPayload != null) {
    const lower = String(outboundPayload).toLowerCase();
    const squeezed = squeezeDigits(outboundPayload);
    for (const o of origList) {
      if (!o || typeof o.value !== 'string') return false;
      const val = o.value;
      if (lower.includes(val.toLowerCase())) return false;
      const d = val.replace(/\D/g, '');
      if (d.length >= 7 && (squeezed.includes(d) || (d.length > 10 && squeezed.includes(d.slice(-10))))) return false;
    }
  }
  if (hmacKeyHex != null) {
    if (origList.length !== a.tags.length) return false;
    for (let i = 0; i < origList.length; i++) {
      if (!origList[i] || typeof origList[i].value !== 'string') return false;
      const expected = await hmacTag(hmacKeyHex, origList[i].value);
      if (a.tags[i].tag !== expected || a.tags[i].type !== origList[i].type) return false;
    }
  }
  return true;
}

// Browser-native fuel-metered WebAssembly Core 1.0 interpreter (i32, f64, linear memory, active data segments, control flow; zero Node imports)
// paired with W3C WebAssembly.validate/instantiate.
function runWasmFuelMetered(bytes, args, fuelLimit = 1000) {
  let pos = 0;
  const u8 = () => { if (pos >= bytes.length) throw new Error('eof'); return bytes[pos++]; };
  const uleb = () => { let res = 0, shift = 0; while (true) { const b = u8(); res |= (b & 0x7f) << shift; if ((b & 0x80) === 0) return res >>> 0; shift += 7; if (shift > 35) throw new Error('uleb'); } };
  const sleb = () => { let res = 0, shift = 0, b; do { b = u8(); res |= (b & 0x7f) << shift; shift += 7; if (shift > 35) throw new Error('sleb'); } while (b & 0x80); if (shift < 32 && (b & 0x40)) res |= (~0 << shift); return res | 0; };
  if (bytes.length < 8) throw new Error('short');
  const magic = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  for (let i = 0; i < 8; i++) if (u8() !== magic[i]) throw new Error('magic');
  const types = [], funcs = [], exports = new Map(), bodies = [];
  const dec = new TextDecoder();
  let memMin = 0, memMax = 16, hasMem = false;
  const dataSegs = [];
  while (pos < bytes.length) {
    const id = u8(), size = uleb(), end = pos + size;
    if (end > bytes.length) throw new Error('section_oob');
    if (id === 1) {
      const n = uleb();
      for (let i = 0; i < n; i++) {
        if (u8() !== 0x60) throw new Error('functype');
        const pc = uleb(), paramTypes = [];
        for (let j = 0; j < pc; j++) paramTypes.push(u8());
        const rc = uleb(), resTypes = [];
        for (let j = 0; j < rc; j++) resTypes.push(u8());
        types.push({ paramTypes, resTypes });
      }
    } else if (id === 3) {
      const n = uleb();
      for (let i = 0; i < n; i++) funcs.push(uleb());
    } else if (id === 5) {
      const n = uleb();
      if (n > 0) {
        hasMem = true;
        const flags = u8();
        memMin = uleb();
        memMax = flags === 1 ? Math.min(uleb(), 16) : 16;
        if (memMin > 16) throw new Error('mem_limit');
        for (let i = 1; i < n; i++) { const f = u8(); uleb(); if (f === 1) uleb(); }
      }
    } else if (id === 7) {
      const n = uleb();
      for (let i = 0; i < n; i++) {
        const nl = uleb();
        const name = dec.decode(bytes.subarray(pos, pos + nl)); pos += nl;
        const kind = u8(), idx = uleb();
        if (kind === 0) exports.set(name, idx);
      }
    } else if (id === 10) {
      const n = uleb();
      for (let i = 0; i < n; i++) {
        const bsize = uleb(), bend = pos + bsize;
        if (bend > end) throw new Error('body_oob');
        const ldecl = uleb();
        const extraTypes = [];
        for (let j = 0; j < ldecl; j++) { const cnt = uleb(), t = u8(); for (let k = 0; k < cnt; k++) extraTypes.push(t); }
        bodies.push({ extraTypes, code: bytes.subarray(pos, bend) });
        pos = bend;
      }
    } else if (id === 11) {
      const n = uleb();
      for (let i = 0; i < n; i++) {
        const mode = uleb();
        if (mode !== 0 || u8() !== 0x41) throw new Error('data_init');
        const offset = sleb();
        if (u8() !== 0x0b) throw new Error('data_end');
        const len = uleb();
        dataSegs.push({ offset, seg: bytes.subarray(pos, pos + len) });
        pos += len;
      }
    } else { pos = end; }
    if (pos !== end) throw new Error('section_len');
  }
  let mem = hasMem ? new Uint8Array(memMin * 65536) : null;
  let memView = mem ? new DataView(mem.buffer) : null;
  for (const { offset, seg } of dataSegs) {
    if (!mem || offset < 0 || offset + seg.length > mem.length) return { trap: 'mem_oob' };
    mem.set(seg, offset);
  }
  const fnIdx = exports.get('main');
  if (fnIdx === undefined || !bodies[fnIdx]) throw new Error('no_main');
  const { paramTypes, resTypes } = types[funcs[fnIdx]];
  const { extraTypes, code } = bodies[fnIdx];
  const localTypes = [...paramTypes, ...extraTypes];
  const locals = localTypes.map((t, i) => {
    const raw = i < paramTypes.length ? (args[i] ?? 0) : 0;
    return t === 0x7c ? Number(raw) : (raw | 0);
  });

  const matchEnd = new Map(), ctrlStack = [];
  for (let ip = 0; ip < code.length; ip++) {
    const op = code[ip];
    if (op === 0x02 || op === 0x03) { ctrlStack.push(ip); ip++; }
    else if (op === 0x0b) { if (ctrlStack.length) matchEnd.set(ctrlStack.pop(), ip); }
    else if (op === 0x0c || op === 0x0d || op === 0x20 || op === 0x21 || op === 0x22 || op === 0x41) { while (code[++ip] & 0x80) {} }
    else if (op === 0x44) { ip += 8; }
    else if (op === 0x28 || op === 0x2b || op === 0x36 || op === 0x39) { while (code[++ip] & 0x80) {} while (code[++ip] & 0x80) {} }
    else if (op === 0x3f || op === 0x40) { ip += 1; }
  }
  const stack = [], labels = [];
  let fuel = fuelLimit, ip = 0;
  const codeView = new DataView(code.buffer, code.byteOffset, code.byteLength);
  const readUlebAt = () => { let r = 0, sh = 0; while (true) { const b = code[ip++]; r |= (b & 0x7f) << sh; if ((b & 0x80) === 0) return r >>> 0; sh += 7; } };
  const readSlebAt = () => { let r = 0, sh = 0, b; do { b = code[ip++]; r |= (b & 0x7f) << sh; sh += 7; } while (b & 0x80); if (sh < 32 && (b & 0x40)) r |= (~0 << sh); return r | 0; };
  const readMemArg = () => { readUlebAt(); return readUlebAt(); };
  while (ip < code.length) {
    if (--fuel < 0) return { trap: 'fuel_exhausted' };
    const op = code[ip++];
    switch (op) {
      case 0x00: return { trap: 'unreachable' };
      case 0x01: break;
      case 0x02: { const start = ip - 1; ip++; labels.push({ loop: false, target: matchEnd.get(start) + 1 }); break; }
      case 0x03: { const start = ip - 1; ip++; labels.push({ loop: true, target: start + 2 }); break; }
      case 0x0b: { if (labels.length) labels.pop(); else return { value: stack.at(-1) ?? 0 }; break; }
      case 0x0c: { const depth = readUlebAt(); const idx = labels.length - 1 - depth; const lbl = labels[idx]; labels.length = lbl.loop ? idx + 1 : idx; ip = lbl.target; break; }
      case 0x0d: { const depth = readUlebAt(); if (stack.pop() !== 0) { const idx = labels.length - 1 - depth; const lbl = labels[idx]; labels.length = lbl.loop ? idx + 1 : idx; ip = lbl.target; } break; }
      case 0x0f: return { value: stack.at(-1) ?? 0 };
      case 0x1a: stack.pop(); break;
      case 0x20: stack.push(locals[readUlebAt()]); break;
      case 0x21: { const i = readUlebAt(); const v = stack.pop(); locals[i] = localTypes[i] === 0x7c ? Number(v) : (v | 0); break; }
      case 0x22: { const i = readUlebAt(); const v = stack.at(-1); locals[i] = localTypes[i] === 0x7c ? Number(v) : (v | 0); break; }
      case 0x28: { const off = readMemArg(); const eff = (stack.pop() >>> 0) + off; if (!mem || eff + 4 > mem.length) return { trap: 'mem_oob' }; stack.push(memView.getInt32(eff, true)); break; }
      case 0x2b: { const off = readMemArg(); const eff = (stack.pop() >>> 0) + off; if (!mem || eff + 8 > mem.length) return { trap: 'mem_oob' }; stack.push(memView.getFloat64(eff, true)); break; }
      case 0x36: { const off = readMemArg(); const val = stack.pop() | 0; const eff = (stack.pop() >>> 0) + off; if (!mem || eff + 4 > mem.length) return { trap: 'mem_oob' }; memView.setInt32(eff, val, true); break; }
      case 0x39: { const off = readMemArg(); const val = Number(stack.pop()); const eff = (stack.pop() >>> 0) + off; if (!mem || eff + 8 > mem.length) return { trap: 'mem_oob' }; memView.setFloat64(eff, val, true); break; }
      case 0x3f: { ip++; stack.push(mem ? (mem.length >>> 16) : 0); break; }
      case 0x40: {
        ip++;
        const delta = stack.pop() >>> 0;
        const curPages = mem ? (mem.length >>> 16) : 0;
        if (!mem || curPages + delta > memMax) { stack.push(-1); break; }
        const next = new Uint8Array((curPages + delta) * 65536);
        next.set(mem);
        mem = next;
        memView = new DataView(mem.buffer);
        stack.push(curPages);
        break;
      }
      case 0x41: stack.push(readSlebAt()); break;
      case 0x44: { stack.push(codeView.getFloat64(ip, true)); ip += 8; break; }
      case 0x45: stack.push(stack.pop() === 0 ? 1 : 0); break;
      case 0x46: { const b = stack.pop(), a = stack.pop(); stack.push(a === b ? 1 : 0); break; }
      case 0x47: { const b = stack.pop(), a = stack.pop(); stack.push(a !== b ? 1 : 0); break; }
      case 0x48: { const b = stack.pop(), a = stack.pop(); stack.push(a < b ? 1 : 0); break; }
      case 0x4a: { const b = stack.pop(), a = stack.pop(); stack.push(a > b ? 1 : 0); break; }
      case 0x4c: { const b = stack.pop(), a = stack.pop(); stack.push(a <= b ? 1 : 0); break; }
      case 0x4e: { const b = stack.pop(), a = stack.pop(); stack.push(a >= b ? 1 : 0); break; }
      case 0x61: { const b = stack.pop(), a = stack.pop(); stack.push(a === b ? 1 : 0); break; }
      case 0x62: { const b = stack.pop(), a = stack.pop(); stack.push(a !== b ? 1 : 0); break; }
      case 0x63: { const b = stack.pop(), a = stack.pop(); stack.push(a < b ? 1 : 0); break; }
      case 0x64: { const b = stack.pop(), a = stack.pop(); stack.push(a > b ? 1 : 0); break; }
      case 0x65: { const b = stack.pop(), a = stack.pop(); stack.push(a <= b ? 1 : 0); break; }
      case 0x66: { const b = stack.pop(), a = stack.pop(); stack.push(a >= b ? 1 : 0); break; }
      case 0x6a: { const b = stack.pop(), a = stack.pop(); stack.push((a + b) | 0); break; }
      case 0x6b: { const b = stack.pop(), a = stack.pop(); stack.push((a - b) | 0); break; }
      case 0x6c: { const b = stack.pop(), a = stack.pop(); stack.push(Math.imul(a, b)); break; }
      case 0x6d: { const b = stack.pop(), a = stack.pop(); if (b === 0 || (a === -2147483648 && b === -1)) return { trap: 'div_by_zero' }; stack.push((a / b) | 0); break; }
      case 0x6f: { const b = stack.pop(), a = stack.pop(); if (b === 0) return { trap: 'div_by_zero' }; stack.push((a % b) | 0); break; }
      case 0x99: stack.push(Math.abs(stack.pop())); break;
      case 0x9a: stack.push(-stack.pop()); break;
      case 0x9b: stack.push(Math.ceil(stack.pop())); break;
      case 0x9c: stack.push(Math.floor(stack.pop())); break;
      case 0x9d: stack.push(Math.trunc(stack.pop())); break;
      case 0x9f: stack.push(Math.sqrt(stack.pop())); break;
      case 0xa0: { const b = stack.pop(), a = stack.pop(); stack.push(a + b); break; }
      case 0xa1: { const b = stack.pop(), a = stack.pop(); stack.push(a - b); break; }
      case 0xa2: { const b = stack.pop(), a = stack.pop(); stack.push(a * b); break; }
      case 0xa3: { const b = stack.pop(), a = stack.pop(); stack.push(a / b); break; }
      case 0xaa: {
        const v = stack.pop();
        if (!Number.isFinite(v)) return { trap: 'invalid_conversion' };
        const t = Math.trunc(v);
        if (t < -2147483648 || t > 2147483647) return { trap: 'invalid_conversion' };
        stack.push(t | 0);
        break;
      }
      case 0xb7: stack.push(Number(stack.pop() | 0)); break;
      default: return { trap: `unsupported_op_${op}` };
    }
  }
  return { value: resTypes[0] === 0x7c ? Number(stack.at(-1) ?? 0) : ((stack.at(-1) ?? 0) | 0) };
}

async function verifyWasmExec({ capsule, revocation = null, args = null, expectOutput = null, expectTrap = null, fuelLimit = 1000 }) {
  if (!await verifyVsc1(capsule) || capsule.runtime !== 'wasm-core-1') return false;
  const bytes = decodeBase64(capsule.code);
  if (!WebAssembly.validate(bytes)) return false;

  if (revocation) {
    if (!await verifyVsc1(revocation) || revocation.spec !== 'vsc-revoke/1') return false;
    if (revocation.targetCodeSha256 !== capsule.codeSha256) return false;
    const ce = revocation.counterexample;
    if (!Array.isArray(ce.input)) return false;
    const fuelRes = runWasmFuelMetered(bytes, ce.input, fuelLimit);
    const { instance } = await WebAssembly.instantiate(bytes);
    const nativeVal = instance.exports.main(...ce.input);
    return !fuelRes.trap && fuelRes.value === nativeVal && fuelRes.value === ce.observed && fuelRes.value !== ce.expected;
  }

  const fuelRes = runWasmFuelMetered(bytes, args || [], fuelLimit);
  if (expectTrap === 'fuel_exhausted') return fuelRes.trap === 'fuel_exhausted';
  if (expectTrap) {
    let nativeTrapped = false;
    try { const { instance } = await WebAssembly.instantiate(bytes); instance.exports.main(...(args || [])); } catch { nativeTrapped = true; }
    return fuelRes.trap === expectTrap && nativeTrapped;
  }
  const { instance } = await WebAssembly.instantiate(bytes);
  const nativeVal = instance.exports.main(...(args || []));
  return !fuelRes.trap && fuelRes.value === nativeVal && fuelRes.value === expectOutput;
}

export async function verifyVector(v) {
  switch (v.suite) {
    case 'jcs': {
      const val = v.input.rawJson != null ? JSON.parse(v.input.rawJson) : v.input.value;
      return canonical(val) === v.input.expected;
    }
    case 'merkle': return verifyMerkle(v.input);
    case 'aer1': return verifyAer1(v.input);
    case 'vsc1': return verifyVsc1(v.input);
    case 'ema1': return verifyEma1(v.input);
    case 'wasm_exec': return verifyWasmExec(v.input);
    default: return false;
  }
}

export async function runConformanceDoc(doc) {
  const t0 = performance.now();
  const failures = [];
  for (const v of doc.vectors) {
    const got = await verifyVector(v);
    if (got !== v.expectOk) failures.push({ id: v.id, suite: v.suite, expected: v.expectOk, got, description: v.description });
  }
  return {
    runtime: 'W3C WebCrypto (globalThis.crypto.subtle, zero node:crypto)',
    total: doc.vectors.length,
    passed: doc.vectors.length - failures.length,
    failed: failures.length,
    durationMs: Math.round((performance.now() - t0) * 100) / 100,
    failures,
  };
}

// CLI entrypoint (dynamically imports node:fs only when executed directly under Node)
if (typeof process !== 'undefined' && process.argv?.[1]?.endsWith('webcrypto-verify.mjs')) {
  const { default: fs } = await import('node:fs');
  const { default: path } = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const vecPath = process.argv[2] || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'vectors.json');
  const doc = JSON.parse(fs.readFileSync(vecPath, 'utf8'));
  const res = await runConformanceDoc(doc);
  console.log(JSON.stringify(res, null, 2));
  process.exit(res.failed === 0 ? 0 : 1);
}
