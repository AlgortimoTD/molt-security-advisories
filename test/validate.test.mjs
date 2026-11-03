import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ROOT } from '../scripts/lib.mjs';
import { validateAll } from '../scripts/validate.mjs';
import { buildFeed, serialize } from '../scripts/build-feed.mjs';

const advisory = () => ({
  schema: 'msa/1', id: 'MSA-2026-0001', title: 'Example product before 2.0.1 runs code from a crafted file',
  summary: 'Example product before 2.0.1 parses a crafted file in a way that lets an attacker run code as the user.',
  status: 'published', published: '2026-11-01', updated: '2026-11-01',
  severity: { level: 'high', urgency: '72h', rationale: 'A crafted file alone triggers the bug; user interaction is needed to open it.' },
  affected: [{ product: 'Example', fixed: '2.0.1' }],
  exposure: 'Anyone who opens files from untrusted sources with Example before 2.0.1.',
  detectors: [{ type: 'executable-version', params: { executable: 'example', ranges: [{ fixed: '2.0.1' }] } }],
  remediation: [{ action: 'Update Example', details: 'Install 2.0.1 or later.', risk: 'Low.' }],
  verification: ['Run example --version and confirm 2.0.1 or later.'],
  sources: [{ url: 'https://example.com/security/2026-01', publisher: 'Example vendor', tier: 1, retrieved: '2026-11-01', supports: ['affected', 'remediation'] }],
  review: { author_model: 'model-a', reviewer_model: 'model-b', reviewed: '2026-11-01', verdict: 'approve', notes: 'Checked against the vendor bulletin.' },
  history: [{ date: '2026-11-01', change: 'Initial publication.' }],
});

function fixture(records) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'msa-test-'));
  fs.cpSync(path.join(ROOT, 'schema'), path.join(dir, 'schema'), { recursive: true });
  for (const record of records) {
    const sub = path.join(dir, record.id.startsWith('MSA') ? 'advisories' : 'rejected', record.id.slice(4, 8));
    fs.mkdirSync(sub, { recursive: true });
    fs.writeFileSync(path.join(sub, `${record.id}.json`), JSON.stringify(record));
  }
  return dir;
}
const problemsFor = record => validateAll(fixture([record])).problems.join('\n');

test('a complete advisory passes', () => {
  assert.deepEqual(validateAll(fixture([advisory()])).problems, []);
});

test('a social post cited as evidence is refused', () => {
  const record = advisory();
  record.sources.push({ url: 'https://x.com/someone/status/1', publisher: 'someone', tier: 1, retrieved: '2026-11-01', supports: ['affected'] });
  assert.match(problemsFor(record), /lead \(tier 3\)/);
});

test('a backed field without a tier 1 source is refused', () => {
  const record = advisory();
  record.sources[0].tier = 2;
  assert.match(problemsFor(record), /affected has no tier 1 source/);
});

test('self review and pending review are refused', () => {
  const same = advisory(); same.review.reviewer_model = 'Model-A';
  assert.match(problemsFor(same), /must differ/);
  const pending = advisory(); pending.review.notes = 'PENDING';
  assert.match(problemsFor(pending), /not filled in/);
});

test('a review older than the last update is refused', () => {
  const record = advisory();
  record.updated = '2026-11-02';
  record.history.push({ date: '2026-11-02', change: 'Corrected the fixed version.' });
  assert.match(problemsFor(record), /review is older/);
});

test('machine inventory is refused', () => {
  const record = advisory();
  record.exposure += ' Seen on /home/alice/.cache/browser.';
  assert.match(problemsFor(record), /inventory/);
});

test('credentials are refused anywhere in a record, URLs included', () => {
  // Synthetic shapes built at runtime, so this file never contains a credential-looking literal.
  for (const fake of ['ghp_' + 'A'.repeat(36), 'AKIA' + 'B'.repeat(16), '-----BEGIN ' + 'OPENSSH PRIVATE KEY-----']) {
    const record = advisory();
    record.exposure += ` ${fake}`;
    assert.match(problemsFor(record), /credential/);
  }
  const record = advisory();
  record.sources[0].url += `?token=${'ghp_' + 'C'.repeat(36)}`;
  assert.match(problemsFor(record), /credential/);
});

test('detector params are checked against the type and the affected versions', () => {
  const bad = advisory(); bad.detectors = [{ type: 'running-process-flag', params: { family: 'chromium', flag: 'no-sandbox' } }];
  assert.match(problemsFor(bad), /invalid params/);
  const mismatch = advisory(); mismatch.detectors = [{ type: 'chromium-browser-version', params: { product: 'chrome', fixed: '9.9.9' } }];
  assert.match(problemsFor(mismatch), /does not match any affected/);
});

test('schema violations, wrong file names and dangling references are reported', () => {
  const record = advisory(); record.severity.level = 'severe'; record.related = ['MSA-2026-0099']; record.extra = true;
  const out = problemsFor(record);
  assert.match(out, /severity\.level: must be one of/);
  assert.match(out, /unexpected property extra/);
  assert.match(out, /related MSA-2026-0099 does not exist/);
});

test('the feed is deterministic and lists rejected claims by summary', () => {
  const rejected = { schema: 'msr/1', id: 'MSR-2026-0001', claim: 'Example 2.0.1 is still vulnerable to the crafted file bug.', verdict: 'false',
    explanation: 'The vendor bulletin lists 2.0.1 as the fixed release and the release notes match it.', published: '2026-11-01', updated: '2026-11-01',
    discovery: [{ url: 'https://x.com/someone/status/2', kind: 'social' }], sources: advisory().sources, related: ['MSA-2026-0001'],
    review: advisory().review, history: advisory().history };
  const dir = fixture([advisory(), rejected]);
  assert.deepEqual(validateAll(dir).problems, []);
  const feed = buildFeed(dir);
  assert.equal(serialize(feed), serialize(buildFeed(dir)));
  assert.equal(feed.advisories[0].id, 'MSA-2026-0001');
  assert.equal(feed.rejected[0].verdict, 'false');
  assert.equal(feed.rejected[0].explanation, undefined);
});
