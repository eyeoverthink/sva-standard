#!/usr/bin/env node
import { detect, SealSession, scanInjection, StreamSealGuard } from '../index.js';

const [cmd, ...rest] = process.argv.slice(2);
const text = rest.join(' ');
if (!cmd || (cmd !== 'stream-demo' && !text)) {
  console.error('usage:\n  privacy-membrane seal "<text>"\n  privacy-membrane scan "<text>"\n  privacy-membrane stream-demo');
  process.exit(2);
}
if (cmd === 'stream-demo') {
  const chunks = ['Using key sk-', 'ant-api03-abcdefghijklmnop1234567890 for SSN 123-', '45-6789 and email elena@', 'northstar.org done.'];
  const guard = new StreamSealGuard();
  const emitted = chunks.map((c) => guard.push(c));
  emitted.push(guard.flush());
  const full = emitted.join('');
  const audit = guard.session.audit(full);
  console.log(JSON.stringify({ chunks, emitted, full, audit, stats: guard.getStats() }, null, 2));
  process.exit(audit.clean ? 0 : 1);
}
if (cmd === 'seal') {
  const spans = detect(text);
  const session = new SealSession();
  const sealed = session.apply(text, spans);
  const audit = session.audit(sealed);
  console.log(JSON.stringify({ sealed, withheld: session.counts, total: session.size, audit }, null, 2));
  process.exit(audit.clean ? 0 : 1);
}
if (cmd === 'scan') {
  const scan = scanInjection(text);
  console.log(JSON.stringify(scan, null, 2));
  process.exit(scan.suspicious ? 1 : 0);
}
console.error(`unknown command: ${cmd}`);
process.exit(2);
