#!/usr/bin/env node
import fs from 'node:fs';
import { verifyReceipt } from '../receipt-verify.js';

const [cmd, file, deliverableFile] = process.argv.slice(2);
if (cmd !== 'verify' || !file) {
  console.error('usage: ai-receipt verify <receipt.json> [deliverable.txt]');
  process.exit(2);
}
const receipt = JSON.parse(fs.readFileSync(file, 'utf8'));
const deliverable = deliverableFile ? fs.readFileSync(deliverableFile, 'utf8') : null;
const res = await verifyReceipt(receipt, { deliverable });
for (const c of res.checks) console.log(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? ` (${c.detail})` : ''}`);
console.log(`\nOUTCOME: ${res.outcome} | deliverable=${res.deliverable} | clock=${res.clock}`);
process.exit(res.ok ? 0 : 1);
