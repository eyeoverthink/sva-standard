// Zero-dependency Streaming Token Guard for LLM NDJSON / text streams.
// Prevents credentials and PII split across arbitrary token boundaries (e.g. "sk-" + "ant-..." or "123-" + "45-6789")
// from leaking mid-stream before sealing/redaction triggers.
// Ported from StreamCanaryInterceptor's cross-token tail-prefix buffering design.
import { detect, SealSession } from './membrane-core.js';

export const SECRET_PREFIXES = [
  'sk-ant-',
  'sk-proj-',
  'sk-',
  'AIza',
  'ghp_',
  'gho_',
  'github_pat_',
  'AKIA',
  'xoxb-',
  'xoxp-',
  'Bearer ',
  '-----BEGIN ',
];

const MAX_PREFIX_LEN = Math.max(...SECRET_PREFIXES.map((p) => p.length));
const CRED_CHAR = /[A-Za-z0-9_\-./+=:]/;

// Returns how many trailing characters of `text` could be the start of a split secret prefix,
// an in-progress token/key, an email local-part, or a partial SSN/phone/card digit run.
export function tailHoldLength(text) {
  if (!text) return 0;
  let hold = 0;

  // 1. Partial match against any known secret prefix (e.g. trailing "sk-" or "ghp")
  const maxCheck = Math.min(text.length, MAX_PREFIX_LEN);
  for (const pfx of SECRET_PREFIXES) {
    for (let len = 1; len <= Math.min(pfx.length, maxCheck); len++) {
      if (text.endsWith(pfx.slice(0, len))) hold = Math.max(hold, len);
    }
  }

  // 2. Active secret prefix still accumulating token chars right up to the end of the chunk
  for (const pfx of SECRET_PREFIXES) {
    const idx = text.lastIndexOf(pfx);
    if (idx !== -1) {
      const tail = text.slice(idx);
      if (/^[A-Za-z0-9_\-./+=: ]+$/.test(tail) && tail.length < 256) {
        hold = Math.max(hold, tail.length);
      }
    }
  }

  // 3. Partial trailing digit/separator run (could become SSN 123-45-6789, phone, or card number)
  const digitTail = text.match(/[+\d][\d\s.\-()]{0,22}$/);
  if (digitTail) hold = Math.max(hold, digitTail[0].length);

  // 4. Partial trailing email-like token containing '@' or identifier before '@'
  const emailTail = text.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*$/);
  if (emailTail) hold = Math.max(hold, emailTail[0].length);

  return Math.min(hold, text.length);
}

export class StreamSealGuard {
  constructor({ session = null, mode = 'seal', maxBuffer = 4096 } = {}) {
    this.session = session || new SealSession();
    this.mode = mode; // 'seal' (typed placeholders) | 'redact' ([REDACTED:<TYPE>])
    this.maxBuffer = maxBuffer;
    this.buffer = '';
    this.chunksProcessed = 0;
    this.sealsApplied = 0;
    this.alerts = [];
  }

  _sealWindow(text) {
    if (!text) return '';
    const spans = detect(text);
    if (spans.length === 0) return text;
    this.sealsApplied += spans.length;
    this.alerts.push({
      chunkIndex: this.chunksProcessed,
      types: [...new Set(spans.map((s) => s.type))],
      count: spans.length,
    });
    if (this.mode === 'redact') {
      let out = '';
      let pos = 0;
      for (const sp of spans) {
        out += text.slice(pos, sp.start) + `[REDACTED:${sp.type}]`;
        pos = sp.end;
      }
      return out + text.slice(pos);
    }
    return this.session.apply(text, spans);
  }

  // Feed one streaming token/chunk; returns the safe-to-emit prefix while holding any boundary-split candidate.
  push(chunk) {
    this.chunksProcessed++;
    const combined = this.buffer + String(chunk ?? '');
    if (!combined) return '';

    // Never hold unbounded memory on adversarial non-whitespace streams
    let hold = tailHoldLength(combined);
    if (hold > this.maxBuffer) hold = 0;

    // Also hold the trailing identifier if we are mid-word next to a potential '@' or secret
    if (hold === 0 && CRED_CHAR.test(combined[combined.length - 1])) {
      const wordTail = combined.match(/[A-Za-z0-9._%+-]{1,32}$/);
      if (wordTail && wordTail[0].length < combined.length) hold = wordTail[0].length;
    }

    const emitRaw = hold > 0 ? combined.slice(0, combined.length - hold) : combined;
    this.buffer = hold > 0 ? combined.slice(combined.length - hold) : '';
    return this._sealWindow(emitRaw);
  }

  // Flush remaining buffered tail at end-of-stream.
  flush() {
    const rest = this.buffer;
    this.buffer = '';
    return this._sealWindow(rest);
  }

  // Process one Ollama-style NDJSON line (supports both /api/generate `.response` and /api/chat `.message.content`).
  processNdjsonLine(line) {
    const parsed = JSON.parse(line);
    if (parsed.response !== undefined) {
      parsed.response = this.push(parsed.response);
      if (parsed.done === true) parsed.response += this.flush();
      return parsed;
    }
    if (parsed.message?.content !== undefined) {
      parsed.message.content = this.push(parsed.message.content);
      if (parsed.done === true) parsed.message.content += this.flush();
      return parsed;
    }
    if (parsed.done === true && this.buffer) {
      parsed.flushedTail = this.flush();
    }
    return parsed;
  }

  // Async generator wrapper for any chunked UTF-8 / string NDJSON stream.
  async *interceptNdjson(readableStream) {
    let lineBuf = '';
    const dec = new TextDecoder();
    for await (const chunk of readableStream) {
      lineBuf += typeof chunk === 'string' ? chunk : dec.decode(chunk, { stream: true });
      const lines = lineBuf.split('\n');
      lineBuf = lines.pop() || '';
      for (const line of lines) {
        if (line.trim()) yield this.processNdjsonLine(line);
      }
    }
    if (lineBuf.trim()) yield this.processNdjsonLine(lineBuf);
    const tail = this.flush();
    if (tail) yield { response: tail, done: true };
  }

  getStats() {
    return {
      chunksProcessed: this.chunksProcessed,
      sealsApplied: this.sealsApplied,
      withheld: { ...this.session.counts },
      alerts: this.alerts.slice(),
    };
  }
}
