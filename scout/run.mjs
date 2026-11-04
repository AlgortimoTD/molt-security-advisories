#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { closeSync } from 'node:fs';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { collect, commitCursor, SOURCES } from './collect.mjs';
import { readX } from './read-x.mjs';
import { command, scopedCommand, ProcessTreeSurvived, privateDir, readJson, writeJson, defaultStateDir, defaultConfigFile, todayBogota, parseMarker, ledgerStart, ledgerEnd } from './common.mjs';
import { changedPaths, guardDiff, stageExactly, restorePath, assertValid, recordId, validateAuthorResult, validateAuthorPaths, validateReviewResult, fillReview, assertHistory } from './records.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const absolute = value => typeof value === 'string' && path.isAbsolute(value);
// The author runs Codex with the user configuration ignored (no configured MCP servers, hooks from
// config.toml or legacy sandbox_mode), every account app, plugin, browser and image tool disabled, and
// a permission profile whose shell can read only the worktree, this run's folder, system runtime
// paths and the Codex package, with no network and a core-only environment. Sources are opened
// through Codex's hosted web search, which never sees local files.
export const AUTHOR_DISABLED_FEATURES = ['apps', 'browser_use', 'browser_use_external', 'browser_use_full_cdp_access', 'computer_use', 'goals', 'image_generation', 'in_app_browser', 'in_app_chat', 'in_app_local_automation', 'multi_agent', 'multi_agent_v2', 'plugins', 'remote_plugin', 'plugin_sharing', 'recommended_plugins', 'skill_mcp_dependency_install', 'tool_suggest', 'view_image', 'workspace_dependencies', 'realtime_conversation', 'memories', 'enable_mcp_apps', 'codex_apps_mcp_2026_07_28', 'request_permissions_tool', 'sleep_tool'];
const toml = value => JSON.stringify(value);
export function authorPermissionArgs({ runDir, codexRoot }) {
  if (![runDir, codexRoot].every(absolute)) throw Error('Author readable roots must be absolute');
  const filesystem = `{":root"="deny", ":minimal"="read", ${toml(codexRoot)}="read", ${toml(runDir)}="read", ":workspace_roots"={"."="write"}}`;
  return ['-c', 'default_permissions="scout"', '-c', `permissions.scout.filesystem=${filesystem}`, '-c', 'shell_environment_policy.inherit="core"'];
}
export const authorFeatureArgs = () => AUTHOR_DISABLED_FEATURES.flatMap(name => ['-c', `features.${name}=false`]);
export const authorArgs = ({ runDir, codexRoot }) => ['--ignore-user-config', '--ignore-rules', '-c', 'approval_policy="never"', ...authorPermissionArgs({ runDir, codexRoot }), '-c', 'web_search="live"', '-c', 'mcp_servers={}', ...authorFeatureArgs()];
// The sandbox re-executes the Codex binary, so the package directory must stay readable.
export function resolveCodexRoot(pathEnv = process.env.PATH || '') {
  for (const dir of pathEnv.split(path.delimiter).filter(absolute)) {
    const candidate = path.join(dir, 'codex');
    let real;
    try { fs.accessSync(candidate, fs.constants.X_OK); real = fs.realpathSync(candidate); } catch { continue; }
    let start = path.dirname(real);
    const head = fs.readFileSync(real).subarray(0, 4096).toString('utf8');
    if (head.startsWith('#!')) {
      const match = head.match(/'(\/[^']*\/@openai\/codex)\/bin\/codex\.js'/);
      if (!match) continue;
      start = match[1];
    }
    for (let current = start; current !== path.dirname(current); current = path.dirname(current)) {
      try { if (readJson(path.join(current, 'package.json'))?.name === '@openai/codex') return fs.realpathSync(current); } catch { /* Keep walking up. */ }
    }
  }
  throw Error('Codex package directory not found');
}
// Fail closed before any model run: every disabled feature must be known and off, no MCP server may
// remain once the user configuration is ignored, and a model-free sandbox probe must be unable to read
// the author's credentials, resolve a host or see secret-looking environment variables.
export async function verifyAuthorIsolation({ exec, worktree, runDir, codexRoot, profile }) {
  const features = await exec('codex', ['features', 'list', ...authorFeatureArgs()], { cwd: worktree, env: { ...process.env, CODEX_HOME: profile }, timeoutMs: 60_000 });
  const state = Object.fromEntries(features.stdout.split('\n').map(line => line.trim().split(/\s+/)).filter(parts => parts.length >= 2).map(parts => [parts[0], parts.at(-1)]));
  const loose = AUTHOR_DISABLED_FEATURES.filter(name => state[name] !== 'false');
  if (loose.length) throw Error(`Author features not disabled: ${loose.join(', ')}`);
  if (fs.existsSync(path.join(worktree, '.codex'))) throw Error('Worktree carries a project Codex configuration');
  const emptyHome = privateDir(path.join(runDir, 'codex-empty-home'));
  const mcp = await exec('codex', ['mcp', 'list', '--json'], { cwd: worktree, env: { ...process.env, CODEX_HOME: emptyHome }, timeoutMs: 60_000 });
  let servers;
  try { servers = JSON.parse(mcp.stdout); } catch { throw Error('Codex MCP inventory is unreadable'); }
  if (!Array.isArray(servers) || servers.length) throw Error('Codex MCP servers remain outside the user configuration');
  const probe = 'cat "$1" >/dev/null 2>&1 && exit 10; ls "$2" >/dev/null 2>&1 && exit 11; getent hosts example.com >/dev/null 2>&1 && exit 12; env | grep -qiE "token|secret|passw|api_?key|credential" && exit 13; exit 0';
  const sandboxed = await exec('codex', ['sandbox', ...authorPermissionArgs({ runDir, codexRoot }), '--', '/bin/sh', '-c', probe, 'probe', path.join(profile, 'auth.json'), profile], { cwd: worktree, env: { ...process.env, CODEX_HOME: emptyHome }, timeoutMs: 60_000, allowFailure: true });
  if (sandboxed.code !== 0) throw Error(`Author sandbox probe failed (exit ${sandboxed.code})`);
  return { features: AUTHOR_DISABLED_FEATURES.length, mcpServers: 0, sandbox: 'confined' };
}
// The reviewer gets no shell: reads are confined to the worktree and this run's private folder,
// and sources are re-read with WebFetch only.
export const reviewTools = (worktree, runDir) => [`Read(/${worktree}/**)`, `Read(/${runDir}/**)`, 'WebFetch'].join(',');
export const REVIEW_AVAILABLE_TOOLS = 'Read,WebFetch';
export function loadConfig(file = defaultConfigFile()) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o777) !== 0o600 || stat.uid !== process.getuid()) throw Error('Configuration must be an owned regular file with mode 600');
  const config = readJson(file);
  config.stateDir ??= defaultStateDir();
  config.llmControlPanelPath ??= path.join(os.homedir(), 'molt/llm-control-panel');
  if (!['repo', 'worktreesDir', 'stateDir', 'ledgerPath', 'llmControlPanelPath'].every(k => absolute(config[k])) || !config.ledgerPath.endsWith('.jsonl')) throw Error('Configuration paths must be absolute; ledgerPath must end in .jsonl');
  for (const [role, provider] of [['author', 'codex'], ['reviewer', 'claude']]) {
    const spec = config[role];
    if (spec?.provider !== provider || !absolute(spec.profile) || typeof spec.model !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,79}$/.test(spec.model) || !Number.isInteger(spec.timeoutS) || spec.timeoutS < 1 || spec.timeoutS > 3000) throw Error(`Invalid ${role} launch specification`);
  }
  if (config.author.model.toLowerCase() === config.reviewer.model.toLowerCase()) throw Error('Author and reviewer must use different models');
  if (!/^\w[\w.-]*$/.test(config.github?.remote ?? '') || config.github.base !== 'main') throw Error('GitHub remote and main base are required');
  if (!/^[a-z0-9][a-z0-9-]{0,53}$/.test(config.notify?.agent ?? '') || typeof config.notify.project !== 'string' || !config.notify.project.trim()) throw Error('Invalid notification identity');
  if (typeof config.dryRun !== 'boolean' || typeof config.x?.enabled !== 'boolean' || !Array.isArray(config.x.searches) || config.x.searches.some(q => typeof q !== 'string' || q.length > 1000) || (config.x.headed !== undefined && typeof config.x.headed !== 'boolean') || (config.x.enabled && (typeof config.x.profile !== 'string' || !config.x.profile || config.x.profile.startsWith('-')))) throw Error('Invalid dryRun or X configuration');
  for (const key of ['timelineMax', 'searchMax']) if (config.x[key] !== undefined && (!Number.isInteger(config.x[key]) || config.x[key] < 1 || config.x[key] > 500)) throw Error('Invalid X post limit');
  if (config.qaBrowser !== undefined && !absolute(config.qaBrowser)) throw Error('qaBrowser must be an absolute executable path');
  if (2 * config.author.timeoutS + 2 * config.reviewer.timeoutS > 9000) throw Error('Model deadlines must leave time for checks and cleanup within the three-hour service bound');
  return config;
}
const hash = value => createHash('sha256').update(value).digest('hex');
async function snapshot(root, exec) {
  const result = {};
  for (const file of await changedPaths(root, exec)) {
    try { result[file] = hash(fs.readFileSync(path.join(root, file))); } catch { result[file] = 'missing'; }
  }
  return JSON.stringify(result);
}
// Phases that always need a person (credentials, isolation, leases, an open PR) notify at once.
// Any other failure is often transient (network, a source outage), so it notifies only when
// it repeats on consecutive runs, and keeps notifying under one stable key while it lasts,
// so a lost delivery is retried on the next failed run. A completed run resets the count.
// Dry runs never touch the count: they must not reset or consume a production failure.
export const IMMEDIATE_BLOCKER_PHASES = ['github-auth', 'merge', 'browser-cleanup', 'process-cleanup', 'author-isolation'];
export const REPEATED_FAILURE_THRESHOLD = 2;
export function recordRunHealth(stateDir, phase) {
  const file = path.join(stateDir, 'run-health.json');
  const consecutiveFailures = phase === null ? 0 : (readJson(file, { consecutiveFailures: 0 }).consecutiveFailures || 0) + 1;
  writeJson(file, { consecutiveFailures, ...(phase === null ? {} : { lastFailedPhase: phase }) });
  const notify = phase !== null && (IMMEDIATE_BLOCKER_PHASES.includes(phase) || consecutiveFailures >= REPEATED_FAILURE_THRESHOLD);
  return { consecutiveFailures, notify };
}

export async function noLeads({ config, cursor, run, cleanup, log = () => {} }) {
  log('no-leads: model-free completion');
  // Keep acknowledgement after cleanup: a failed cleanup must not consume leads.
  await cleanup();
  commitCursor(config.stateDir, cursor);
  if (!config.dryRun) recordRunHealth(config.stateDir, null);
  ledgerEnd(config.ledgerPath, run, { outcome: 'no-leads', modelInvoked: false });
  return { outcome: 'no-leads', modelInvoked: false };
}

export async function runScout(config, dependencies = {}) {
  const exec = dependencies.exec || command;
  const collectLeads = dependencies.collect || collect, readSocial = dependencies.readX || readX;
  const now = dependencies.now || (() => new Date());
  const log = dependencies.log || (line => process.stderr.write(`scout: ${line}\n`));
  const wait = dependencies.wait || (ms => new Promise(resolve => setTimeout(resolve, ms)));
  privateDir(config.stateDir);
  privateDir(path.dirname(config.ledgerPath));
  const runtimeFile = path.join(config.llmControlPanelPath, 'scripts/agent-run.mjs');
  const acquireLock = dependencies.acquireLock || (await import(pathToFileURL(runtimeFile).href)).acquireLock;
  const held = acquireLock(path.join(config.stateDir, 'scout.lock'));
  if (held.fd === undefined) {
    fs.appendFileSync(config.ledgerPath, JSON.stringify({ schema: 'agent-run/1', event: 'skipped', runId: randomUUID(), agent: config.notify.agent, at: now().toISOString(), trigger: { kind: 'timer' }, reason: held.busy ? 'lock-busy' : 'lock-unavailable' }) + '\n', { mode: 0o600 });
    return { exitCode: held.busy ? 75 : 1, outcome: held.busy ? 'busy' : 'lock-unavailable' };
  }
  let run, runDir;
  const date = todayBogota(now());
  try {
    run = ledgerStart(config.ledgerPath, { agent: config.notify.agent, cwd: config.repo, now: now() });
    runDir = privateDir(path.join(config.stateDir, 'runs', `${date}-${run.runId}`));
  } catch (error) { closeSync(held.fd); throw error; }
  let worktree, branch, baseSha, modelInvoked = false, finished = false, phase = 'preflight', repository;
  const sourceRejections = [], dropped = [], modelsById = new Map();
  let worktreeCreated = false, survived = false, codexRoot;
  const git = (args, options = {}) => exec('git', args, { cwd: worktree || config.repo, ...options });
  const notify = async (kind, id, title, need) => {
    if (config.dryRun) { log(`dry-run: would notify ${kind}`); return; }
    await exec('agent-approval', ['notify', '--agent', config.notify.agent, '--project', config.notify.project, '--kind', kind, '--title', title, '--need', need, '--key', `molt-security-scout:${id}`], { timeoutMs: 30_000 });
  };
  const cleanup = async () => {
    if (!worktree || !worktreeCreated) return;
    // Preserve uncommitted candidate records privately before removing our exact worktree.
    for (const file of await changedPaths(worktree, exec)) {
      if (/^(advisories|rejected)\/\d{4}\/MS[AR]-\d{4}-\d{4}\.json$/.test(file)) {
        const source = path.join(worktree, file);
        if (fs.existsSync(source) && fs.lstatSync(source).isFile()) {
          const target = path.join(runDir, 'candidates', file);
          privateDir(path.dirname(target)); fs.copyFileSync(source, target); fs.chmodSync(target, 0o600);
        }
      }
    }
    await exec('git', ['worktree', 'remove', '--force', worktree], { cwd: config.repo, timeoutMs: 60_000 });
    worktree = undefined; worktreeCreated = false;
  };
  const guard = async () => {
    if ((await git(['rev-parse', 'HEAD'])).stdout.trim() !== baseSha) throw Error('Model changed the branch HEAD');
    const result = await guardDiff(worktree, exec);
    sourceRejections.push(...result.rejected);
    writeJson(path.join(runDir, 'diff-guard.json'), { reverted: sourceRejections });
    await assertHistory(worktree, result.allowed, exec);
    assertValid(worktree, { pending: true });
    return result.allowed;
  };
  const modelRun = async (role, round, context) => {
    phase = role;
    log(`${role}: ${round}`);
    const spec = config[role], marker = role === 'author' ? 'SCOUT_RESULT' : 'REVIEW_RESULT';
    const promptFile = path.join(runDir, `${role}-${round}.md`);
    const template = fs.readFileSync(path.join(HERE, 'prompts', `${role}.md`), 'utf8');
    fs.writeFileSync(promptFile, `${template}\n\n## Supervisor context\n\nToday: ${date} (America/Bogota).\nWorktree: ${worktree}\nLeads: ${path.join(runDir, 'leads.json')}\n${context}\n`, { mode: 0o600 });
    const emptyMcp = path.join(runDir, 'mcp.json');
    writeJson(emptyMcp, { mcpServers: {} });
    const extra = role === 'author' ? authorArgs({ runDir, codexRoot }) : ['--allowedTools', reviewTools(worktree, runDir), '--tools', REVIEW_AVAILABLE_TOOLS, '--permission-mode', 'dontAsk', '--strict-mcp-config', '--mcp-config', emptyMcp];
    // Launching is an attempted invocation. The host runner records the observed value separately.
    modelInvoked = true;
    const unit = `molt-security-scout-${role}-${randomUUID()}`;
    const output = await scopedCommand(unit, process.execPath, [runtimeFile, '--agent', `${config.notify.agent}-${role}`, '--ledger', config.ledgerPath, '--provider', spec.provider, '--cwd', worktree, '--prompt-file', promptFile, '--profile', spec.profile, '--model', spec.model, '--timeout', String(spec.timeoutS), '--trigger', `timer:${date}`, '--outcome-marker', marker, '--', ...extra], { cwd: worktree, timeoutMs: (spec.timeoutS + 45) * 1000 }, { exec });
    const result = parseMarker(output.stdout, marker);
    if (result.status !== 'completed') throw Error(`${role} did not complete`);
    // Runtime observations win over a requested alias. Codex may supply only its own exact name.
    const rows = fs.readFileSync(config.ledgerPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    const start = rows.findLast(r => r.event === 'start' && r.agent === `${config.notify.agent}-${role}`);
    const end = start && rows.findLast(r => r.event === 'end' && r.runId === start.runId);
    if (!end || end.status !== 'ok' || end.modelInvoked !== true) throw Error(`${role} runtime did not attest a complete invocation`);
    writeJson(path.join(runDir, `${role}-${round}-result.json`), result);
    return { result, observedModel: end.model };
  };
  try {
    log('preflight: verify repository and SSH remote');
    privateDir(path.dirname(config.ledgerPath));
    const remote = (await git(['remote', 'get-url', '--push', config.github.remote])).stdout.trim();
    const match = remote.match(/^git@github\.com:([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?$/);
    if (!match) throw Error('Publishing remote must use GitHub SSH');
    repository = match[1];
    if ((await git(['status', '--porcelain'])).stdout) throw Error('Canonical repository must be clean');
    log('worktree: fetch main and allocate daily branch');
    await git(['fetch', config.github.remote, 'main'], { timeoutMs: 120_000 });
    baseSha = (await git(['rev-parse', `${config.github.remote}/main`])).stdout.trim();
    fs.mkdirSync(config.worktreesDir, { recursive: true, mode: 0o700 });
    for (let n = 1; ; n++) {
      branch = `scout/${date}${n === 1 ? '' : `-${n}`}`;
      const local = await git(['show-ref', '--verify', '--quiet', `refs/heads/${branch}`], { allowFailure: true });
      const remoteBranch = await git(['ls-remote', '--heads', config.github.remote, `refs/heads/${branch}`], { timeoutMs: 60_000 });
      const target = path.join(config.worktreesDir, branch.replace('/', '-'));
      if (local.code === 1 && !remoteBranch.stdout.trim() && !fs.existsSync(target)) { worktree = target; break; }
      if (n > 100) throw Error('Daily branch allocation exhausted');
    }
    await exec('git', ['worktree', 'add', '-b', branch, worktree, baseSha], { cwd: config.repo, timeoutMs: 60_000 });
    worktreeCreated = true;
    phase = 'collect'; log('collect: official sources and optional X leads');
    const collected = await collectLeads({ cursor: readJson(path.join(config.stateDir, 'cursor.json'), { sources: {} }), now: now() });
    const x = await readSocial({ ...config.x, qaBrowser: config.qaBrowser || path.join(config.llmControlPanelPath, 'skills/qa-browser-run/bin/qa-browser'), runDir: path.join(runDir, 'browser') });
    writeJson(path.join(runDir, 'leads.json'), { official: collected.items, sourceErrors: collected.sourceErrors, x });
    for (const error of collected.sourceErrors) log(`collect: ${error.source} unavailable (${error.reason})`);
    const xHealthFile = path.join(config.stateDir, 'x-health.json');
    const previousHealth = readJson(xHealthFile, { signedOutRuns: 0 });
    const signedOutRuns = x.reason === 'signed-out' ? previousHealth.signedOutRuns + 1 : 0;
    writeJson(xHealthFile, { signedOutRuns });
    if (signedOutRuns === 3) await notify('blocker', 'x-signed-out', 'Security scout X profile is signed out', 'Three consecutive runs found a login wall or an X account screen instead of the timeline. Sign in or complete it using the configured browser profile. Official feeds continue.');
    if (x.reason === 'browser-stop-failed') { phase = 'browser-cleanup'; throw Error('Browser stop failed; profile lease needs attention'); }
    if (collected.sourceErrors.length === SOURCES.length) throw Error('All official sources failed');
    if (!collected.items.length && !x.posts?.length) {
      const result = await noLeads({ config, cursor: collected.nextCursor, run, cleanup, log });
      finished = true; return { ...result, exitCode: 0 };
    }
    phase = 'author-isolation'; log('author-isolation: verify tools, MCP inventory and sandbox');
    codexRoot = dependencies.codexRoot || resolveCodexRoot();
    writeJson(path.join(runDir, 'author-isolation.json'), await (dependencies.verifyAuthorIsolation || verifyAuthorIsolation)({ exec, worktree, runDir, codexRoot, profile: config.author.profile }));
    const authored = await modelRun('author', 'initial', 'Investigate these leads. No previous findings.');
    let files = await guard();
    let authorModel = validateAuthorResult(authored.result, files, authored.observedModel);
    await validateAuthorPaths(worktree, authored.result, files, exec);
    for (const file of files) modelsById.set(recordId(file), authorModel);
    const initialIds = new Set(files.map(recordId));
    let review;
    if (files.length) {
      for (let round = 0; round < 2; round++) {
        const before = await snapshot(worktree, exec);
        const diff = (await git(['diff', 'HEAD', '--', 'advisories', 'rejected'])).stdout;
        // Include untracked records, which git diff does not show.
        const candidates = files.map(file => ({ path: file, record: readJson(path.join(worktree, file)) }));
        const diffFile = path.join(runDir, `review-${round}-diff.json`);
        writeJson(diffFile, { authorModel, diff, candidates });
        const reviewed = await modelRun('reviewer', String(round + 1), `Author exact model: ${authorModel}.\nRead the exact diff and candidate records at ${diffFile}.`);
        if ((await git(['rev-parse', 'HEAD'])).stdout.trim() !== baseSha || before !== await snapshot(worktree, exec)) throw Error('Reviewer modified the worktree');
        review = validateReviewResult(reviewed.result, files, authorModel, reviewed.observedModel);
        if (review.records.every(r => r.verdict === 'approve') || round === 1) break;
        const findingsFile = path.join(runDir, 'fix-findings.json'); writeJson(findingsFile, review);
        const fixed = await modelRun('author', 'fix', `Read independent findings at ${findingsFile}. This is the only fix round. Return the full current diff, not just this round's edits. Do not add new record IDs.`);
        files = await guard();
        if (files.some(file => !initialIds.has(recordId(file)))) throw Error('Fix round introduced an unreviewed new record');
        authorModel = validateAuthorResult(fixed.result, files, fixed.observedModel);
        await validateAuthorPaths(worktree, fixed.result, files, exec);
        for (const file of files) modelsById.set(recordId(file), authorModel);
      }
      phase = 'review-filter'; log('review-filter: remove records without final approval');
      for (const file of files) {
        const verdict = review.records.find(r => r.id === recordId(file));
        if (verdict?.verdict !== 'approve') { dropped.push({ id: recordId(file), findings: verdict?.findings || [] }); await restorePath(worktree, file, exec); }
      }
      files = files.filter(file => !dropped.some(r => r.id === recordId(file)));
      writeJson(path.join(runDir, 'dropped-records.json'), dropped);
      for (const file of files) writeJson(path.join(worktree, file), fillReview(readJson(path.join(worktree, file)), { authorModel: modelsById.get(recordId(file)), reviewerModel: review.model, date, review: review.records.find(r => r.id === recordId(file)) }));
    }
    const records = files.map(file => ({ file, record: readJson(path.join(worktree, file)) }));
    let prUrl;
    if (files.length) {
      phase = 'gate'; log('gate: build feed and run complete repository checks');
      await exec('npm', ['run', 'feed'], { cwd: worktree, timeoutMs: 120_000 });
      await exec('npm', ['run', 'check'], { cwd: worktree, timeoutMs: 300_000 });
      phase = 'commit'; log('commit: approved records and generated feed');
      await stageExactly(worktree, [...files, 'feed.json'], exec);
      // Re-run the path guard on what is about to be committed: nothing outside records and the feed.
      const outside = (await changedPaths(worktree, exec)).filter(file => file !== 'feed.json' && !files.includes(file));
      if (outside.length) throw Error('Unapproved paths changed before commit');
      await git(['commit', '-m', `Scout ${date}: ${files.map(recordId).join(', ')}`], { timeoutMs: 60_000 });
      if (config.dryRun) log(`dry-run: would push ${branch}, open a PR, require green checks, and squash merge`);
      else {
        phase = 'github-auth'; log('github: check API authentication');
        await exec('gh', ['auth', 'status'], { timeoutMs: 20_000 });
        phase = 'push'; log('push: task branch over SSH');
        await git(['push', '-u', config.github.remote, branch], { timeoutMs: 120_000 });
        phase = 'pull-request'; log('pull-request: open reviewed change');
        const bodyFile = path.join(runDir, 'pr-body.md');
        fs.writeFileSync(bodyFile, `Verified security records from the daily scout. Every included record has an independent approval.\n\n${records.map(({ record }) => `- ${record.id}: ${record.title || record.claim}. Severity: ${record.severity?.level || 'rejected claim'}. Sources: ${record.sources.length}. Review: approve (${review.model}).`).join('\n')}\n\nValidation: npm run feed and npm run check passed.\n`, { mode: 0o600 });
        prUrl = (await exec('gh', ['pr', 'create', '--repo', repository, '--base', 'main', '--head', branch, '--title', `Scout ${date}: ${files.map(recordId).join(', ')}`, '--body-file', bodyFile], { cwd: worktree, timeoutMs: 60_000 })).stdout.trim();
        if (!new RegExp(`^https://github\\.com/${repository.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/pull/\\d+$`).test(prUrl)) throw Error('Unexpected PR URL');
        const head = (await git(['rev-parse', 'HEAD'])).stdout.trim();
        phase = 'merge'; log('merge: poll checks and mergeability, at most 15 minutes');
        await waitForChecks({ exec, wait, now, repository, prUrl, head });
        // Detach our worktree so the daily branch is no longer checked out anywhere.
        await git(['switch', '--detach', head]);
        await exec('gh', ['pr', 'merge', prUrl, '--repo', repository, '--squash', '--delete-branch', '--match-head-commit', head], { cwd: config.repo, timeoutMs: 120_000 });
        const merged = JSON.parse((await exec('gh', ['pr', 'view', prUrl, '--repo', repository, '--json', 'state'], { timeoutMs: 30_000 })).stdout);
        if (merged.state !== 'MERGED') throw Error('PR merge was not confirmed');
        // With --repo, gh deletes only the remote branch. The squash merge is confirmed for this
        // exact head, so the local branch holds nothing unpublished: remove it so none accumulate.
        const removed = await git(['branch', '-D', branch], { allowFailure: true, timeoutMs: 30_000 });
        if (removed.code !== 0) log(`merge: local branch ${branch} could not be deleted; remove it after checking it is merged`);
      }
    }
    phase = 'notify'; log('notify: publication risks and non-quiet daily summary');
    if (files.length && !config.dryRun) {
      for (const { file, record } of records) if (record.id.startsWith('MSA-') && authored.result.created.includes(record.id) && ['critical', 'high'].includes(record.severity.level)) {
        await notify('risk', record.id, record.title, `${record.severity.level}: ${record.summary.replace(/\s+/g, ' ').slice(0, 220)} https://github.com/${repository}/blob/main/${file}`);
      }
    }
    if (files.length || dropped.length) await notify('info', date, `Security scout ${date}`, `${config.dryRun ? 'Local dry-run commit' : 'Published'}: ${files.map(recordId).join(', ') || 'none'}. Withheld after review: ${dropped.map(r => r.id).join(', ') || 'none'}. Reverted out-of-scope paths: ${sourceRejections.length}. ${prUrl || ''}`);
    phase = 'cleanup'; log('cleanup: acknowledge cursor and remove worktree');
    await cleanup();
    commitCursor(config.stateDir, collected.nextCursor);
    if (!config.dryRun) recordRunHealth(config.stateDir, null);
    const outcome = config.dryRun && files.length ? 'dry-run-committed' : files.length ? 'published' : dropped.length ? 'withheld' : 'no-records';
    ledgerEnd(config.ledgerPath, run, { outcome, modelInvoked, now: now() }); finished = true;
    return { exitCode: 0, outcome, branch, records: files.map(recordId), dropped: dropped.map(r => r.id), prUrl };
  } catch (error) {
    if (error instanceof ProcessTreeSurvived) { survived = true; phase = 'process-cleanup'; }
    writeJson(path.join(runDir, 'failure.json'), { phase, reason: error.message });
    log(`failed: ${phase}; cursor not acknowledged`);
    // Without a trustworthy count, notify rather than risk staying silent.
    let health = { consecutiveFailures: 0, notify: true, untracked: true };
    if (config.dryRun) health = { consecutiveFailures: 0, notify: IMMEDIATE_BLOCKER_PHASES.includes(phase) };
    else try { health = recordRunHealth(config.stateDir, phase); } catch { log('health: could not record the failure count'); }
    if (health.notify) {
      const repeated = !IMMEDIATE_BLOCKER_PHASES.includes(phase);
      try { await notify('blocker', repeated ? 'repeated-failure' : `${date}-${phase}`, 'Security scout needs attention', `${repeated ? health.untracked ? `Run failed during ${phase} and the failure count could not be recorded.` : `${health.consecutiveFailures} consecutive runs failed; the latest failed during ${phase}.` : `Run failed during ${phase}.`} Review the private run evidence and host ledger. The cursor was not acknowledged, so no lead is lost.`); } catch { log('notify: failed to deliver blocker'); }
    } else log(`notify: failure ${health.consecutiveFailures} of ${REPEATED_FAILURE_THRESHOLD} before a blocker notice`);
    return { exitCode: 1, outcome: 'failed', phase };
  } finally {
    if (!finished) {
      // A model process may still be running: leave its worktree in place for a human to inspect.
      if (survived) log('cleanup: skipped, a model process tree survived termination');
      else try { await cleanup(); } catch { log('cleanup: worktree removal failed; inspect the private run directory'); }
      ledgerEnd(config.ledgerPath, run, { outcome: 'failed', status: 'failed', modelInvoked, now: now() });
    }
    closeSync(held.fd);
  }
}

export async function waitForChecks({ exec, wait, now, repository, prUrl, head, maxMs = 15 * 60_000 }) {
  const deadline = now().getTime() + maxMs;
  for (let poll = 0; poll < 31 && now().getTime() < deadline; poll++) {
    const view = JSON.parse((await exec('gh', ['pr', 'view', prUrl, '--repo', repository, '--json', 'headRefOid,mergeable,mergeStateStatus,statusCheckRollup'], { timeoutMs: 30_000 })).stdout);
    if (view.headRefOid !== head) throw Error('PR head changed after review');
    const checks = view.statusCheckRollup || [];
    const passed = c => c.__typename === 'CheckRun' ? c.status === 'COMPLETED' && c.conclusion === 'SUCCESS' : c.state === 'SUCCESS';
    const failed = c => c.__typename === 'CheckRun' ? c.status === 'COMPLETED' && !['SUCCESS', 'NEUTRAL', 'SKIPPED'].includes(c.conclusion) : ['ERROR', 'FAILURE'].includes(c.state);
    if (checks.some(failed) || view.mergeable === 'CONFLICTING') throw Error('PR checks failed or merge conflicts exist');
    // Empty, skipped, neutral and unknown checks never count as green.
    if (checks.length > 0 && checks.every(passed) && view.mergeable === 'MERGEABLE' && view.mergeStateStatus === 'CLEAN') return;
    await wait(Math.min(30_000, Math.max(0, deadline - now().getTime())));
  }
  throw Error('PR checks did not become green and mergeable in 15 minutes');
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.umask(0o077);
    const args = process.argv.slice(2);
    if (args.length && (args.length !== 2 || args[0] !== '--config')) throw Error('Usage: node scout/run.mjs [--config FILE]');
    process.exitCode = (await runScout(loadConfig(args[1]))).exitCode;
  } catch (error) { process.stderr.write(`scout: ${error.message}\n`); process.exitCode = 1; }
}
