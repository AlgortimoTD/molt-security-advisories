// Shared helpers for the validator and the feed builder. No dependencies on purpose:
// a security feed should not pull third-party code into its own gate.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export const readJson = file => JSON.parse(fs.readFileSync(file, 'utf8'));

/** Lists record files as { file, dir } for advisories/ and rejected/, sorted by path. */
export function recordFiles(root = ROOT) {
  const out = [];
  for (const dir of ['advisories', 'rejected']) {
    const base = path.join(root, dir);
    if (!fs.existsSync(base)) continue;
    for (const year of fs.readdirSync(base).sort()) {
      const yearDir = path.join(base, year);
      if (!fs.statSync(yearDir).isDirectory()) continue;
      for (const name of fs.readdirSync(yearDir).sort()) {
        if (name.endsWith('.json')) out.push({ file: path.join(yearDir, name), dir, year });
      }
    }
  }
  return out;
}

/**
 * Validates a value against the JSON Schema subset these schemas use: type, const, enum,
 * required, properties, additionalProperties: false, items, minItems, uniqueItems,
 * minLength, maxLength, pattern and $ref (local or to a sibling schema file).
 */
export function validateSchema(value, schema, { schemas, here, at = '$' }) {
  const errors = [];
  const resolve = (ref, current) => {
    const [file, pointer = ''] = ref.split('#');
    const doc = schemas[file || current];
    if (!doc) throw Error(`Unknown schema reference ${ref}`);
    const node = pointer.split('/').filter(Boolean).reduce((acc, key) => acc?.[key], doc);
    if (!node) throw Error(`Unresolvable schema reference ${ref}`);
    return { node, file: file || current };
  };
  const walk = (val, sch, where, file) => {
    if (sch.$ref) {
      const { node, file: target } = resolve(sch.$ref, file);
      walk(val, node, where, target);
      const rest = { ...sch }; delete rest.$ref;
      if (Object.keys(rest).length) walk(val, rest, where, file);
      return;
    }
    const kind = Array.isArray(val) ? 'array' : val === null ? 'null' : typeof val;
    if (sch.type) {
      const ok = sch.type === 'integer' ? Number.isInteger(val) : sch.type === kind;
      if (!ok) { errors.push(`${where}: expected ${sch.type}, got ${kind}`); return; }
    }
    if ('const' in sch && val !== sch.const) errors.push(`${where}: must be ${JSON.stringify(sch.const)}`);
    if (sch.enum && !sch.enum.includes(val)) errors.push(`${where}: must be one of ${sch.enum.map(v => JSON.stringify(v)).join(', ')}`);
    if (kind === 'string') {
      if (sch.minLength !== undefined && val.length < sch.minLength) errors.push(`${where}: shorter than ${sch.minLength}`);
      if (sch.maxLength !== undefined && val.length > sch.maxLength) errors.push(`${where}: longer than ${sch.maxLength}`);
      if (sch.pattern && !new RegExp(sch.pattern, 'u').test(val)) errors.push(`${where}: does not match ${sch.pattern}`);
    }
    if (kind === 'array') {
      if (sch.minItems !== undefined && val.length < sch.minItems) errors.push(`${where}: needs at least ${sch.minItems} item(s)`);
      if (sch.uniqueItems && new Set(val.map(v => JSON.stringify(v))).size !== val.length) errors.push(`${where}: items must be unique`);
      if (sch.items) val.forEach((item, i) => walk(item, sch.items, `${where}[${i}]`, file));
    }
    if (kind === 'object') {
      for (const key of sch.required ?? []) if (!(key in val)) errors.push(`${where}: missing ${key}`);
      for (const [key, item] of Object.entries(val)) {
        if (sch.properties?.[key]) walk(item, sch.properties[key], `${where}.${key}`, file);
        else if (sch.additionalProperties === false) errors.push(`${where}: unexpected property ${key}`);
      }
    }
  };
  walk(value, schema, at, here);
  return errors;
}

/** Compares dotted numeric versions; returns -1, 0 or 1. */
export function compareVersions(a, b) {
  const pa = String(a).split('.').map(Number), pb = String(b).split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
