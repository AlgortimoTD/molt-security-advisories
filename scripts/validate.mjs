#!/usr/bin/env node
// Gate for every record: schema, identifiers, dates, evidence tiers, review and hygiene.
// Exit code 0 means every record is publishable; 1 lists each problem found.
import path from 'node:path';
import { ROOT, readJson, recordFiles, validateSchema } from './lib.mjs';

const BACKED = ['affected', 'cve', 'vendor_severity', 'exploitation', 'remediation'];
// Tier 3 hosts are leads only; they may appear in `discovery`, never in `sources`.
const LEAD_HOSTS = /(^|\.)(x\.com|twitter\.com|t\.co|reddit\.com|news\.ycombinator\.com|linkedin\.com|facebook\.com|threads\.net|bsky\.app|mastodon\.social|youtube\.com|medium\.com|substack\.com)$/i;
// Advisories describe products, never a machine: these patterns indicate inventory.
// Credential shapes, checked everywhere in a record including URLs: a public feed never carries one.
const SECRETS = [/\bgh[pousr]_[A-Za-z0-9]{30,}/, /\bgithub_pat_[A-Za-z0-9_]{40,}/, /\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/, /\bAKIA[0-9A-Z]{16}\b/, /\bxox[abprs]-[A-Za-z0-9-]{10,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/, /\bAIza[0-9A-Za-z_-]{35}\b/, /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/];
const INVENTORY = [/\/home\/[a-z0-9_.-]+/i, /\/Users\/[A-Za-z0-9_.-]+/, /[A-Z]:\\Users\\/i, /\b(?:\d{1,3}\.){3}\d{1,3}\b/, /\.ts\.net\b/i, /\blocalhost:\d+/i];
const DETECTOR_PARAMS = {
  'chromium-browser-version': p => typeof p.product === 'string' && /^\d+(\.\d+)+$/.test(p.fixed ?? ''),
  'running-process-flag': p => typeof p.family === 'string' && /^--[a-z0-9-]+$/.test(p.flag ?? ''),
  'executable-version': p => typeof p.executable === 'string' && Array.isArray(p.ranges) && p.ranges.length > 0 && p.ranges.every(r => r.fixed || r.introduced),
  'package-version': p => ['npm', 'PyPI', 'Go', 'crates.io'].includes(p.ecosystem) && typeof p.name === 'string' && Array.isArray(p.ranges) && p.ranges.length > 0 && p.ranges.every(r => r.fixed || r.introduced),
  manual: p => typeof p.instructions === 'string' && p.instructions.length >= 20,
};

export function validateAll(root = ROOT) {
  const schemas = {
    'advisory.schema.json': readJson(path.join(root, 'schema', 'advisory.schema.json')),
    'rejected.schema.json': readJson(path.join(root, 'schema', 'rejected.schema.json')),
  };
  const problems = [], records = new Map();
  const files = recordFiles(root);
  for (const { file, dir, year } of files) {
    const rel = path.relative(root, file);
    const fail = msg => problems.push(`${rel}: ${msg}`);
    let record;
    try { record = readJson(file); } catch (error) { fail(`invalid JSON (${error.message})`); continue; }
    const here = dir === 'advisories' ? 'advisory.schema.json' : 'rejected.schema.json';
    for (const error of validateSchema(record, schemas[here], { schemas, here })) fail(error);
    const prefix = dir === 'advisories' ? 'MSA' : 'MSR';
    if (typeof record.id !== 'string') continue;
    if (!record.id.startsWith(`${prefix}-`)) fail(`${dir}/ holds only ${prefix} records`);
    if (path.basename(file, '.json') !== record.id) fail(`file name must be ${record.id}.json`);
    if (record.id.slice(4, 8) !== year) fail(`id year does not match folder ${year}`);
    if (records.has(record.id)) fail(`duplicate id ${record.id}`);
    records.set(record.id, { record, rel, dir });
  }
  for (const [id, { record, rel, dir }] of records) {
    const fail = msg => problems.push(`${rel}: ${msg}`);
    // Dates: published <= updated, history ordered, first entry on publication day, last on updated.
    if (record.published && record.updated && record.updated < record.published) fail('updated is before published');
    const history = record.history ?? [];
    history.forEach((entry, i) => { if (i && entry.date < history[i - 1].date) fail('history dates must be in order'); });
    if (history.length && history[0].date !== record.published) fail('first history entry must be the publication date');
    if (history.length && history.at(-1).date !== record.updated) fail('last history entry must match updated');
    // Review: complete, and by a model other than the author.
    const review = record.review ?? {};
    for (const key of ['author_model', 'reviewer_model', 'notes']) {
      if (typeof review[key] === 'string' && /PENDING|TODO|TBD/i.test(review[key])) fail(`review.${key} is not filled in`);
    }
    if (review.author_model && review.reviewer_model && review.author_model.trim().toLowerCase() === review.reviewer_model.trim().toLowerCase()) fail('reviewer_model must differ from author_model');
    if (review.reviewed && record.updated && review.reviewed < record.updated) fail('review is older than the last update; review the current record');
    // Sources: no leads, every backed field cites tier 1.
    const sources = record.sources ?? [];
    for (const source of sources) {
      let host = '';
      try { host = new URL(source.url).hostname; } catch { fail(`source URL ${source.url} is not valid`); continue; }
      if (LEAD_HOSTS.test(host)) fail(`${host} is a lead (tier 3); move it to discovery`);
    }
    const tier1 = new Set(sources.filter(s => s.tier === 1).flatMap(s => s.supports));
    if (dir === 'advisories') {
      for (const field of BACKED) {
        const present = Array.isArray(record[field]) ? record[field].length > 0 : record[field] !== undefined;
        if (present && !tier1.has(field)) fail(`${field} has no tier 1 source in sources[].supports`);
      }
      if (record.status === 'withdrawn' && !record.withdrawn_reason) fail('withdrawn records need withdrawn_reason');
      if (record.status !== 'withdrawn' && record.withdrawn_reason) fail('withdrawn_reason is only for withdrawn records');
      for (const [i, detector] of (record.detectors ?? []).entries()) {
        const check = DETECTOR_PARAMS[detector.type];
        if (check && !check(detector.params ?? {})) fail(`detectors[${i}] has invalid params for ${detector.type}`);
      }
      const fixed = (record.affected ?? []).map(a => a.fixed).filter(Boolean);
      for (const [i, detector] of (record.detectors ?? []).entries()) {
        if (detector.type === 'chromium-browser-version' && fixed.length && !fixed.includes(detector.params?.fixed)) fail(`detectors[${i}].params.fixed does not match any affected[].fixed`);
      }
    } else if (!tier1.size) fail('a rejected claim needs at least one tier 1 source');
    // Cross references resolve.
    for (const ref of record.related ?? []) if (!records.has(ref)) fail(`related ${ref} does not exist`);
    if ((record.related ?? []).includes(id)) fail('a record cannot relate to itself');
    // No inventory anywhere in the record.
    const text = JSON.stringify(record);
    for (const pattern of INVENTORY) if (pattern.test(text.replace(/https:\/\/[^"\s]+/g, ''))) fail(`looks like machine inventory (${pattern}); advisories describe products, not hosts`);
    for (const pattern of SECRETS) if (pattern.test(text)) fail('looks like a credential; a public record never contains secrets');
  }
  return { problems, count: records.size };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { problems, count } = validateAll();
  if (problems.length) {
    console.error(`${problems.length} problem(s) in ${count} record(s):`);
    for (const line of problems) console.error(`- ${line}`);
    process.exit(1);
  }
  console.log(`${count} record(s) valid.`);
}
