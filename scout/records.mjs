import fs from 'node:fs';
import path from 'node:path';
import { validateAll } from '../scripts/validate.mjs';

export const RECORD_PATH = /^(advisories\/\d{4}\/MSA-\d{4}-\d{4}|rejected\/\d{4}\/MSR-\d{4}-\d{4})\.json$/;
export const recordId = file => path.posix.basename(file, '.json');
export const pendingOnly = problem => /: review\.(?:reviewer_model|notes) is not filled in$/.test(problem);
export function assertValid(root, { pending = false } = {}) {
  const { problems } = validateAll(root);
  const failures = pending ? problems.filter(p => !pendingOnly(p)) : problems;
  if (failures.length) throw Error(`Record validation failed: ${failures.join('; ')}`);
}
// Index and working tree are inspected separately: a change present only in the index would
// otherwise be invisible to `git diff HEAD` and could ride along with an approved record.
export async function changedPaths(root, exec) {
  const staged = await exec('git', ['diff', '--cached', 'HEAD', '--no-renames', '--name-only', '-z'], { cwd: root });
  const unstaged = await exec('git', ['diff', '--no-renames', '--name-only', '-z'], { cwd: root });
  const untracked = await exec('git', ['ls-files', '--others', '-z'], { cwd: root });
  return [...new Set((staged.stdout + unstaged.stdout + untracked.stdout).split('\0').filter(Boolean))].sort();
}
// Models never decide what is staged. Reset the index to HEAD, keeping working files for the guard.
export async function clearIndex(root, exec) {
  await exec('git', ['reset', '--quiet', '--mixed', 'HEAD'], { cwd: root });
  const left = await exec('git', ['diff', '--cached', 'HEAD', '--name-only', '-z'], { cwd: root });
  if (left.stdout) throw Error('Index still differs from HEAD after reset');
}
// The supervisor stages exactly the approved files and verifies the complete staged diff.
export async function stageExactly(root, files, exec) {
  await clearIndex(root, exec);
  await exec('git', ['add', '--', ...files], { cwd: root });
  const staged = (await exec('git', ['diff', '--cached', 'HEAD', '--no-renames', '--name-only', '-z'], { cwd: root })).stdout.split('\0').filter(Boolean).sort();
  const expected = [...new Set(files)].sort();
  // Every staged path must be approved; an approved file may be absent only if it did not change.
  if (!staged.length || staged.some(file => !expected.includes(file))) throw Error('Staged changes differ from the approved files');
  return staged;
}
export async function restorePath(root, file, exec) {
  if (path.isAbsolute(file) || file.split('/').includes('..')) throw Error('Unsafe git path');
  const tracked = await exec('git', ['ls-tree', '-z', 'HEAD', '--', file], { cwd: root });
  if (tracked.stdout) await exec('git', ['restore', '--source=HEAD', '--staged', '--worktree', '--', file], { cwd: root });
  else {
    // Remove only an exact path reported by git, including untracked and ignored files.
    await exec('git', ['rm', '--cached', '--ignore-unmatch', '--', file], { cwd: root });
    fs.rmSync(path.join(root, file), { force: true, recursive: false });
  }
}
export async function guardDiff(root, exec) {
  const before = await changedPaths(root, exec);
  await clearIndex(root, exec);
  const after = await changedPaths(root, exec);
  // Changes that existed only in the index are gone now; record them as rejected for the evidence.
  const rejected = before.filter(file => !after.includes(file)), allowed = [];
  for (const file of after) {
    let regular = false;
    try { regular = fs.lstatSync(path.join(root, file)).isFile(); } catch { /* A deletion is never allowed. */ }
    const parts = file.split('/');
    let safeParents = true;
    for (let i = 1; i < parts.length; i++) {
      try { if (!fs.lstatSync(path.join(root, ...parts.slice(0, i))).isDirectory()) safeParents = false; } catch { safeParents = false; }
    }
    if (!RECORD_PATH.test(file) || !regular || !safeParents) { await restorePath(root, file, exec); rejected.push(file); }
    else allowed.push(file);
  }
  return { allowed, rejected };
}
export function validateAuthorResult(result, files, observedModel) {
  const model = observedModel || result.model;
  if (typeof model !== 'string' || !model.trim() || /pending|unknown|default|todo/i.test(model)) throw Error('Author exact model is missing');
  if (observedModel && result.model && result.model !== observedModel) throw Error('Author model disagrees with runtime observation');
  if (!Array.isArray(result.created) || !Array.isArray(result.updated) || !Array.isArray(result.skipped)) throw Error('Invalid SCOUT_RESULT');
  const ids = [...result.created, ...result.updated];
  if (ids.some(id => typeof id !== 'string') || new Set(ids).size !== ids.length || JSON.stringify(ids.slice().sort()) !== JSON.stringify(files.map(recordId).sort())) throw Error('Author result does not match changed records');
  return model;
}
export async function validateAuthorPaths(root, result, files, exec) {
  for (const file of files) {
    const baseline = await exec('git', ['ls-tree', '--name-only', 'HEAD', '--', file], { cwd: root });
    const existing = baseline.stdout.trim() === file;
    if (!(existing ? result.updated : result.created).includes(recordId(file))) throw Error('Author misclassified a new or existing record');
  }
}
export function validateReviewResult(result, files, authorModel, observedModel) {
  if (typeof result.model !== 'string' || !result.model.trim() || /pending|unknown|default|todo/i.test(result.model) || result.model.trim().toLowerCase() === authorModel.trim().toLowerCase()) throw Error('Independent reviewer exact model is required');
  if (observedModel && observedModel !== result.model) throw Error('Reviewer model disagrees with runtime observation');
  if (!Array.isArray(result.records)) throw Error('Invalid REVIEW_RESULT');
  const ids = result.records.map(r => r.id);
  if (new Set(ids).size !== ids.length || JSON.stringify(ids.slice().sort()) !== JSON.stringify(files.map(recordId).sort())) throw Error('Review does not cover exactly the changed records');
  for (const r of result.records) {
    if (!['approve', 'changes'].includes(r.verdict) || !Array.isArray(r.findings)) throw Error('Invalid review verdict');
    for (const f of r.findings) if (!['blocker', 'major', 'minor'].includes(f.severity) || !['field', 'issue', 'fix'].every(k => typeof f[k] === 'string' && f[k].trim())) throw Error('Invalid review finding');
    if (r.verdict === 'approve' && r.findings.length) throw Error('Approval with open findings is invalid');
  }
  return result;
}
export function fillReview(record, { authorModel, reviewerModel, date, review }) {
  if (review.id !== record.id || review.verdict !== 'approve' || !Array.isArray(review.findings) || review.findings.length || !authorModel || !reviewerModel || authorModel.trim().toLowerCase() === reviewerModel.trim().toLowerCase() || date < record.updated) throw Error('Cannot fill an unapproved review');
  return { ...record, review: { author_model: authorModel, reviewer_model: reviewerModel, reviewed: date, verdict: 'approve', notes: 'Independent reviewer re-read every tier 1 source and checked every field. No open findings.' } };
}
export async function assertHistory(root, files, exec) {
  for (const file of files) {
    const previous = await exec('git', ['show', `HEAD:${file}`], { cwd: root, allowFailure: true });
    if (previous.code !== 0) continue;
    const before = JSON.parse(previous.stdout), after = JSON.parse(fs.readFileSync(path.join(root, file), 'utf8'));
    if (after.id !== before.id || after.published !== before.published || after.updated < before.updated || after.history.length <= before.history.length || JSON.stringify(after.history.slice(0, before.history.length)) !== JSON.stringify(before.history)) throw Error('An existing record needs an append-only correction history');
  }
}
