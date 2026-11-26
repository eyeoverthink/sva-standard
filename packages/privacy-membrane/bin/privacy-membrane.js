#!/usr/bin/env node
import { detect, SealSession, scanInjection } from '../index.js';

const [cmd, ...rest] = process.argv.slice(2);
const text = rest.join(' ');
if (!cmd || !text) {
  console.error('usage:\n  privacy-membrane seal "<text>"\n  privacy-membrane scan "<text>"');
  process.exit(2);
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
