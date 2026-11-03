import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';

export const defaultStateDir = () => path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), '.local/state'), 'molt-security-scout');
export const defaultConfigFile = () => path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'molt-security-scout/config.json');
export const todayBogota = (now = new Date()) => new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Bogota', year: 'numeric', month: '2-digit', day: '2-digit' }).format(now);
export function privateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()) throw Error('Unsafe private directory');
  fs.chmodSync(dir, 0o700);
  return dir;
}
export function writeJson(file, value) {
  const tmp = `${file}.${randomUUID()}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  fs.renameSync(tmp, file);
}
export function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) { if (error.code === 'ENOENT') return fallback; throw error; }
}

// No shell, no command output in errors. Provider responses and credentials stay out of logs.
export async function command(file, args, { cwd, env = process.env, timeoutMs = 60_000, allowFailure = false, maxBytes = 16 * 1024 * 1024 } = {}) {
  return await new Promise((resolve, reject) => {
    let child, stdout = '', stderr = '', failure, expired = false;
    const kill = () => { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* Already gone. */ } };
    try { child = spawn(file, args, { cwd, env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch { reject(Error(`${path.basename(file)} could not start`)); return; }
    let drain;
    const timer = setTimeout(() => { expired = true; kill(); drain = setTimeout(() => { child.stdout.destroy(); child.stderr.destroy(); }, 1000); }, timeoutMs);
    child.on('error', () => { failure = 'could not start'; });
    const collect = key => chunk => {
      if (key === 'stdout') stdout += chunk; else stderr += chunk;
      if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > maxBytes) { failure = 'output limit'; kill(); }
    };
    child.stdout.on('data', collect('stdout')); child.stderr.on('data', collect('stderr'));
    child.on('close', code => {
      clearTimeout(timer); clearTimeout(drain);
      if (expired || failure || (code !== 0 && !allowFailure)) reject(Error(`${path.basename(file)} ${expired ? 'timed out' : failure || `failed (exit ${code})`}`));
      else resolve({ code, stdout, stderr });
    });
  });
}

export function parseMarker(text, marker) {
  const matches = text.split(/\r?\n/).filter(line => line.startsWith(`${marker} `) || line.startsWith(`${marker}=`));
  if (!matches.length) throw Error(`Missing ${marker}`);
  const values = matches.map(line => JSON.parse(line.slice(marker.length + 1)));
  if (values.some(value => !value || typeof value !== 'object' || Array.isArray(value))) throw Error(`Invalid ${marker}`);
  if (values.some(value => JSON.stringify(value) !== JSON.stringify(values[0]))) throw Error(`Conflicting ${marker}`);
  return values[0];
}

export function ledgerStart(file, { agent, cwd, runId = randomUUID(), now = new Date() }) {
  privateDir(path.dirname(file));
  fs.appendFileSync(file, JSON.stringify({ schema: 'agent-run/1', event: 'start', runId, agent, at: now.toISOString(), trigger: { kind: 'timer' }, cwd, provider: null, tools: [], mcp: 'none', modelInvoked: false }) + '\n', { mode: 0o600 });
  return { runId, started: now };
}
export function ledgerEnd(file, run, { outcome, status = 'ok', modelInvoked = false, now = new Date() }) {
  fs.appendFileSync(file, JSON.stringify({ schema: 'agent-run/1', event: 'end', runId: run.runId, at: now.toISOString(), durationS: Math.max(0, (now - run.started) / 1000), status, exitCode: status === 'ok' ? 0 : 1, modelInvoked, outcome }) + '\n', { mode: 0o600 });
}
