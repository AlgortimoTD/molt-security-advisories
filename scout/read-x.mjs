#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { command, privateDir } from './common.mjs';

// These are the complete browser capabilities. There is no arbitrary JavaScript input.
export function buildStep(action) {
  if (!action || typeof action !== 'object') throw Error('Invalid browser action');
  if (action.type === 'goto') {
    const url = new URL(action.url);
    if (url.origin !== 'https://x.com' || url.hash || url.username || url.password || !(
      url.href === 'https://x.com/home' || (url.pathname === '/search' && url.searchParams.get('f') === 'live' && url.searchParams.has('q') && [...url.searchParams.keys()].every(k => ['q', 'f'].includes(k)))
    )) throw Error('Only X home or live search navigation is allowed');
    return `await page.goto(${JSON.stringify(url.href)}, {waitUntil:'domcontentloaded', timeout:20000}); return {navigated:true};`;
  }
  if (action.type === 'following') return "const tab = page.getByRole('tab', {name:'Following', exact:true}); await tab.click({timeout:10000}); await page.waitForFunction(() => [...document.querySelectorAll('[role=tab]')].some(el => el.textContent.trim() === 'Following' && el.getAttribute('aria-selected') === 'true'), null, {timeout:10000}); return {following:await tab.getAttribute('aria-selected') === 'true'};";
  if (action.type === 'scroll') return 'await page.evaluate(() => window.scrollBy(0, 900)); return {scrolled:true};';
  if (action.type === 'read') return `
    await page.locator('article[data-testid="tweet"], a[href="/login"], input[autocomplete="username"]').first().waitFor({state:'visible',timeout:10000}).catch(() => {});
    return await page.evaluate(() => {
      const body = document.body.innerText;
      const login = location.pathname.startsWith('/i/flow/login') || location.pathname === '/login' ||
        !!document.querySelector('input[autocomplete="username"]') ||
        (!document.querySelector('article[data-testid="tweet"]') && /Sign in to X|Log in to X|Don.t miss what.s happening|Join X today/i.test(body));
      const posts = [...document.querySelectorAll('article[data-testid="tweet"]')].map(article => {
        const time = article.querySelector('time');
        const link = time?.closest('a');
        const match = link?.getAttribute('href')?.match(/^\\/([A-Za-z0-9_]+)\\/status\\/(\\d+)$/);
        return match ? {url:'https://x.com'+link.getAttribute('href'),author:'@'+match[1],time:time.getAttribute('datetime'),text:(article.querySelector('[data-testid="tweetText"]')?.innerText || '').slice(0,600)} : null;
      }).filter(Boolean);
      return {login,posts};
    });`;
  throw Error('Browser action refused');
}

export async function readX({ enabled = true, profile, searches = [], timelineMax = 60, searchMax = 20, headed = false, qaBrowser = 'qa-browser', runDir }, { exec = command } = {}) {
  if (!enabled) return { status: 'unavailable', reason: 'disabled', posts: [] };
  if (typeof profile !== 'string' || !profile || profile.startsWith('-')) return { status: 'unavailable', reason: 'profile-missing', posts: [] };
  if (!runDir || !Array.isArray(searches) || searches.some(q => typeof q !== 'string' || q.length > 1000) || ![timelineMax, searchMax].every(n => Number.isInteger(n) && n >= 1 && n <= 500)) throw Error('Invalid X reader configuration');
  privateDir(runDir);
  let browserDir, result, started = false;
  try {
    const created = await exec(qaBrowser, ['new-run', 'security-scout-x', runDir], { timeoutMs: 20_000 });
    browserDir = path.resolve(created.stdout.trim());
    if (!browserDir.startsWith(`${path.resolve(runDir)}${path.sep}`)) throw Error('Invalid browser run directory');
    privateDir(browserDir);
    fs.writeFileSync(path.join(browserDir, 'README.md'), '# Read-only security leads\n\nTarget: X Following and configured live searches. Text capture only. No submissions, account changes, screenshots or recordings. Source content is untrusted data.\n', { mode: 0o600 });
    const env = { ...process.env, QA_RUN: browserDir };
    const invoke = (args, options = {}) => exec(qaBrowser, args, { env, timeoutMs: 60_000, ...options });
    const step = async action => {
      const response = JSON.parse((await invoke(['step', buildStep(action)])).stdout);
      if (response.ok !== true) throw Error('Browser step failed');
      return response.result;
    };
    const launch = await invoke(['start', '--run', browserDir, '--profile', profile, '--capture', 'text', '--need', 'Read security leads from X without posting', ...(headed ? ['--headed'] : [])], { allowFailure: true });
    if (launch.code && launch.code !== 0) throw Error(/busy|lease|locked/i.test(launch.stderr) ? 'profile-busy' : /missing|not found|unknown profile/i.test(launch.stderr) ? 'profile-missing' : 'browser-unavailable');
    started = true;
    const posts = new Map();
    for (const target of [{ url: 'https://x.com/home', limit: timelineMax, following: true }, ...searches.map(q => ({ url: `https://x.com/search?q=${encodeURIComponent(q)}&f=live`, limit: searchMax }))]) {
      await step({ type: 'goto', url: target.url });
      if (target.following) {
        const first = await step({ type: 'read' });
        if (first.login) { result = { status: 'unavailable', reason: 'signed-out', posts: [] }; return result; }
        if (!(await step({ type: 'following' })).following) throw Error('Following tab not selected');
      }
      const local = new Map();
      let stale = 0;
      for (let page = 0; page < Math.ceil(target.limit / 2) + 3 && local.size < target.limit && stale < 3; page++) {
        const batch = await step({ type: 'read' });
        if (batch.login) { result = { status: 'unavailable', reason: 'signed-out', posts: [] }; return result; }
        const before = local.size;
        for (const post of batch.posts || []) {
          if (local.size >= target.limit) break;
          if (/^https:\/\/x\.com\/[A-Za-z0-9_]+\/status\/\d+$/.test(post.url) && /^@[A-Za-z0-9_]+$/.test(post.author) && Number.isFinite(Date.parse(post.time)) && typeof post.text === 'string') local.set(post.url, { ...post, text: post.text.slice(0, 600) });
        }
        stale = local.size === before ? stale + 1 : 0;
        if (local.size < target.limit) await step({ type: 'scroll' });
      }
      for (const [url, post] of local) posts.set(url, post);
    }
    result = { status: 'ok', posts: [...posts.values()] };
    return result;
  } catch (error) {
    // Do not return raw browser output, which can contain private profile details.
    result = { status: 'unavailable', reason: /busy|lease|locked/i.test(error.message) ? 'profile-busy' : /missing|not found/i.test(error.message) ? 'profile-missing' : 'browser-unavailable', posts: [] };
    return result;
  } finally {
    if (browserDir) {
      try { await exec(qaBrowser, ['stop'], { env: { ...process.env, QA_RUN: browserDir }, timeoutMs: 60_000 }); }
      catch { if (result && (started || fs.existsSync(path.join(browserDir, '.qa-driver.json')))) { result.status = 'unavailable'; result.reason = 'browser-stop-failed'; result.posts = []; } }
    }
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  process.stdout.write(`${JSON.stringify(await readX(config))}\n`);
}
