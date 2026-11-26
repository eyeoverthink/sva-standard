#!/usr/bin/env node
import { induce, leaveOneOut, applySpec, novelWording } from '../binder-induction.js';

const skill = {
  name: 'sequential_discount',
  params: {
    type: 'object',
    properties: {
      price: { type: 'number', description: 'original price' },
      d1: { type: 'number', description: 'first discount as decimal fraction' },
      d2: { type: 'number', description: 'second discount as decimal fraction' },
    },
  },
};
const pos = [
  { task: 'A $100 jacket is 20% off, then an extra 10% off. What is the final price?', input: { price: 100, d1: 0.2, d2: 0.1 } },
  { task: 'A $80 pair of shoes is 15% off, then an extra 20% off. What is the final price?', input: { price: 80, d1: 0.15, d2: 0.2 } },
  { task: 'A $150 backpack is 30% off, then an extra 5% off. What is the final price?', input: { price: 150, d1: 0.3, d2: 0.05 } },
];
const neg = [{ task: 'A $200 desk is 20% off, then 8% sales tax is added. What is the final price?' }];

const task = process.argv.slice(2).join(' ') || 'A $240 coat is 25% off, then an extra 10% off. What is the final price?';
const { spec } = induce(pos, neg, skill);
const loo = leaveOneOut(pos, neg, skill);
const bound = applySpec(spec, task);
const novel = novelWording(pos, task);
const routed = Boolean(bound && novel.length === 0);
const answer = routed ? Math.round(bound.price * (1 - bound.d1) * (1 - bound.d2) * 100) / 100 : null;
console.log(JSON.stringify({ task, leaveOneOut: `${loo.filter((r) => r.ok).length}/${loo.length}`, routed, modelCalls: 0, bound, novelWording: novel, answer }, null, 2));
