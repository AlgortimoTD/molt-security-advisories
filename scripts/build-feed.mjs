#!/usr/bin/env node
// Builds feed.json, the single file consumers fetch. Deterministic: the same records always
// produce the same bytes, so CI can check the committed feed with --check.
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, readJson, recordFiles } from './lib.mjs';
import { validateAll } from './validate.mjs';

export function buildFeed(root = ROOT) {
  const advisories = [], rejected = [];
  for (const { file, dir } of recordFiles(root)) {
    const record = readJson(file);
    if (dir === 'advisories') advisories.push(record);
    else rejected.push({ id: record.id, claim: record.claim, verdict: record.verdict, published: record.published, updated: record.updated, related: record.related ?? [], url: `https://github.com/AlgortimoTD/molt-security-advisories/blob/main/rejected/${record.id.slice(4, 8)}/${record.id}.json` });
  }
  const byId = (a, b) => a.id.localeCompare(b.id);
  advisories.sort(byId); rejected.sort(byId);
  const updated = [...advisories, ...rejected].map(r => r.updated).sort().at(-1) ?? null;
  return {
    schema: 'msa-feed/1',
    publisher: 'MOLT Security Advisories',
    homepage: 'https://github.com/AlgortimoTD/molt-security-advisories',
    updated,
    advisories,
    rejected,
  };
}

export const serialize = feed => `${JSON.stringify(feed, null, 2)}\n`;

if (import.meta.url === `file://${process.argv[1]}`) {
  const { problems } = validateAll();
  if (problems.length) { console.error('Records are not valid; run npm run validate.'); process.exit(1); }
  const target = path.join(ROOT, 'feed.json'), next = serialize(buildFeed());
  if (process.argv.includes('--check')) {
    const current = fs.existsSync(target) ? fs.readFileSync(target, 'utf8') : '';
    if (current !== next) { console.error('feed.json is out of date; run npm run feed and commit it.'); process.exit(1); }
    console.log('feed.json is up to date.');
  } else {
    fs.writeFileSync(target, next);
    console.log(`feed.json written (${JSON.parse(next).advisories.length} advisories).`);
  }
}
