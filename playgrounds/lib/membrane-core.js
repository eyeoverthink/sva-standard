// Browser-pure Privacy Membrane core extracted directly from src/guard/membrane.js (zero Node imports).
// Runs identically in Node.js and modern browsers with zero dependencies.

const OPEN = '⟦', CLOSE = '⟧';

function luhn(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

const DETECTORS = [
  ['SECRET', /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g],
  ['SECRET', /\b(?:sk|pk|rk)-[A-Za-z0-9_-]{20,}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bAIza[0-9A-Za-z_-]{30,}\b|\bxox[abpr]-[A-Za-z0-9-]{10,}\b|\bAKIA[0-9A-Z]{16}\b/g],
  ['SECRET', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
  ['SECRET', /(?<=\b(?:password|passwd|passcode|pin|secret|api[_-]?key|token)\s*(?:is|[:=])\s*["']?)[^\s"',;]{4,}/gi],
  ['URL', /\bhttps?:\/\/[^\s<>"')]+[?&](?:token|key|sig|signature|auth|access_token|password)=[^\s<>"')]+/gi],
  ['EMAIL', /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  ['IBAN', /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}(?:\s?[A-Z0-9]{1,4})?\b/g],
  ['CARD', /\b(?:\d[ -]?){12,18}\d\b/g],
  ['SSN', /\b\d{3}-\d{2}-\d{4}\b/g],
  ['PHONE', /(?:\+\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)[\s.-]?|\b\d{2,4}[\s.-])\d{3,4}[\s.-]\d{3,4}\b/g],
  ['IP', /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g],
  ['PERSON', /\b(?:Dr|Mr|Mrs|Ms|Mx|Prof|Sr|Sra|Herr|Frau)\.?\s+[A-Z][a-z'’-]+(?:\s+[A-Z][a-z'’-]+){0,2}/g],
  ['ADDRESS', /\b\d{1,6}\s+(?:[A-Z][a-z]+\s+){1,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Way|Court|Ct|Place|Pl|Terrace|Parkway|Pkwy|Highway|Hwy)\b\.?(?:,\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)?/g],
  ['ID', /\b[A-Z]{2,5}-\d{5,}\b/g],
  ['ID', /(?<=\b(?:account|acct|patient|customer|member|policy|case|invoice)\s*(?:no\.?|number|#|id)?\s*[:#]?\s*)\d{5,}\b/gi],
];

const VALIDATE = {
  CARD: (v) => { const d = v.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d); },
  PHONE: (v) => { const d = v.replace(/\D/g, ''); return d.length >= 10 && d.length <= 15; },
  IBAN: (v) => v.replace(/\s/g, '').length >= 15,
};

export function detect(text, { terms = [] } = {}) {
  const s = String(text ?? '');
  const spans = [];
  for (const [type, re] of DETECTORS) {
    re.lastIndex = 0;
    for (const m of s.matchAll(re)) {
      let value = m[0].trim();
      if (type === 'SECRET' || type === 'URL' || type === 'EMAIL') value = value.replace(/[.,;:!?)]+$/, '');
      if (!value || (VALIDATE[type] && !VALIDATE[type](value))) continue;
      const start = m.index + m[0].indexOf(value);
      spans.push({ start, end: start + value.length, type, value });
    }
  }
  for (const term of terms) {
    const t = String(term || '').trim();
    if (t.length < 2) continue;
    const re = new RegExp(`(?<![\\p{L}\\p{N}])${t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![\\p{L}\\p{N}])`, 'giu');
    for (const m of s.matchAll(re)) spans.push({ start: m.index, end: m.index + m[0].length, type: 'TERM', value: m[0] });
  }
  spans.sort((a, b) => a.start - b.start || (b.end - b.start) - (a.end - a.start));
  const out = [];
  for (const sp of spans) {
    const last = out.at(-1);
    if (last && sp.start < last.end) {
      if (sp.end - sp.start > last.end - last.start) out[out.length - 1] = sp;
      continue;
    }
    out.push(sp);
  }
  return out;
}

const digitsOnly = (v) => v.replace(/\D/g, '');
const squeezeDigits = (s) => s.replace(/(?<=\d)[\s.\-()]+(?=\d)/g, '');

export class SealSession {
  constructor() { this.byValue = new Map(); this.byPlaceholder = new Map(); this.counts = {}; }

  placeholder(type, value) {
    const key = value.toLowerCase();
    if (this.byValue.has(key)) return this.byValue.get(key);
    this.counts[type] = (this.counts[type] || 0) + 1;
    const ph = `${OPEN}${type}_${this.counts[type]}${CLOSE}`;
    this.byValue.set(key, ph);
    this.byPlaceholder.set(ph, { type, value });
    return ph;
  }

  apply(text, spans) {
    let out = '', i = 0;
    for (const sp of spans) { out += text.slice(i, sp.start) + this.placeholder(sp.type, sp.value); i = sp.end; }
    return out + text.slice(i);
  }

  get size() { return this.byPlaceholder.size; }
  values() { return [...this.byPlaceholder.values()]; }

  unseal(text, { json = false } = {}) {
    let s = String(text ?? '');
    for (const [ph, { type, value }] of this.byPlaceholder) {
      const n = ph.slice(OPEN.length + type.length + 1, -CLOSE.length);
      const re = new RegExp(`(?:${OPEN}|\\[\\[?|«|<)?\\b${type}_${n}\\b(?:${CLOSE}|\\]\\]?|»|>)?`, 'g');
      const rep = json ? JSON.stringify(value).slice(1, -1) : value;
      s = s.replace(re, () => rep);
    }
    return s;
  }

  audit(payload) {
    const p = String(payload ?? '');
    const lower = p.toLowerCase();
    const squeezed = squeezeDigits(p);
    const leaks = [];
    for (const { type, value } of this.values()) {
      if (lower.includes(value.toLowerCase())) { leaks.push(type); continue; }
      const d = digitsOnly(value);
      if (d.length >= 7 && (squeezed.includes(d) || (d.length > 10 && squeezed.includes(d.slice(-10))))) leaks.push(type);
    }
    return { clean: leaks.length === 0, leaks };
  }
}

export class MembraneLeak extends Error {
  constructor(leaks, message = null) {
    super(message || `membrane blocked egress: ${leaks.length} sensitive value(s) would have left the machine (${[...new Set(leaks)].join(', ')})`);
    this.leaks = leaks;
  }
}

export const MEMBRANE_NOTE = `Some values in this conversation were replaced by placeholders such as ${OPEN}EMAIL_1${CLOSE} or ${OPEN}PERSON_2${CLOSE} to protect privacy. Treat each placeholder as the real value it stands for, keep placeholders EXACTLY as written (same brackets, type and number) wherever the value belongs in your answer, and never try to guess what they hide.`;
