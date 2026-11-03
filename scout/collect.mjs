#!/usr/bin/env node
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { defaultStateDir, readJson, privateDir, writeJson } from './common.mjs';

const RELEASES = ['microsoft/playwright', 'microsoft/playwright-mcp', 'anthropics/claude-code', 'openai/codex', 'git/git', 'nodejs/node'];
export const SOURCES = [
  { source: 'chrome', format: 'atom', url: 'https://chromereleases.googleblog.com/feeds/posts/default' },
  { source: 'kev', format: 'kev', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
  { source: 'ghsa', format: 'ghsa', url: 'https://api.github.com/advisories?type=reviewed&per_page=100&sort=published&direction=desc' },
  { source: 'node', format: 'rss', url: 'https://nodejs.org/en/feed/vulnerability.xml' },
  { source: 'ubuntu', format: 'rss', url: 'https://ubuntu.com/security/notices/rss.xml' },
  ...RELEASES.map(repo => ({ source: `release:${repo}`, format: 'atom', url: `https://github.com/${repo}/releases.atom` })),
];
const DAY = 86_400_000;
export function decodeXml(text) {
  return text.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/&#(x[\da-f]+|\d+);/gi, (_, n) => {
    const value = n[0].toLowerCase() === 'x' ? parseInt(n.slice(1), 16) : Number(n);
    return value <= 0x10ffff ? String.fromCodePoint(value) : '';
  }).replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}
export const plainText = text => decodeXml(decodeXml(text).replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
const tag = (xml, name) => xml.match(new RegExp(`<(?:[\\w-]+:)?${name}\\b[^>]*>([\\s\\S]*?)<\\/(?:[\\w-]+:)?${name}>`, 'i'))?.[1] ?? '';
const attr = (xml, name) => decodeXml(xml.match(new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, 'i'))?.[1] ?? '');
export function parseXml(xml) {
  if (!/<(?:[\w-]+:)?(?:feed|rss|RDF)\b/i.test(xml)) throw Error('Invalid XML feed');
  return [...xml.matchAll(/<(?:[\w-]+:)?(entry|item)\b[^>]*>([\s\S]*?)<\/(?:[\w-]+:)?\1>/gi)].map(([, , body]) => {
    const links = [...body.matchAll(/<(?:[\w-]+:)?link\b[^>]*>/gi)].map(m => m[0]);
    const link = links.find(l => attr(l, 'rel') === 'alternate') || links.find(l => !attr(l, 'rel'));
    // Blogger feeds (Chrome Releases) publish http:// links; every collected host serves https.
    const url = (attr(link || '', 'href') || decodeXml(tag(body, 'link')).trim()).replace(/^http:\/\//i, 'https://');
    return { id: decodeXml(tag(body, 'id') || tag(body, 'guid')).trim() || url, title: plainText(tag(body, 'title')), url,
      published: plainText(tag(body, 'published') || tag(body, 'pubDate') || tag(body, 'updated') || tag(body, 'date')),
      summary: plainText(tag(body, 'content') || tag(body, 'description') || tag(body, 'summary')) };
  });
}
export function parseSource(spec, body) {
  let entries;
  if (spec.format === 'kev') {
    const value = JSON.parse(body);
    if (!Array.isArray(value.vulnerabilities)) throw Error('Invalid KEV feed');
    entries = value.vulnerabilities.map(v => ({ id: v.cveID, title: `${v.cveID}: ${v.vulnerabilityName}`, url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${encodeURIComponent(v.cveID)}`, published: v.dateAdded, summary: v.shortDescription || '' }));
  } else if (spec.format === 'ghsa') {
    const value = JSON.parse(body);
    if (!Array.isArray(value)) throw Error('Invalid advisory feed');
    entries = value.filter(v => ['high', 'critical'].includes(v.severity) && v.vulnerabilities?.some(x => ['npm', 'pip', 'go', 'actions'].includes(x.package?.ecosystem)))
      .map(v => ({ id: v.ghsa_id, title: v.summary, url: v.html_url, published: v.published_at, summary: v.description || '' }));
  } else entries = parseXml(body);
  return entries.filter(v => {
    if (spec.source === 'chrome') return /(?:stable|extended stable).*\b(?:desktop|windows|mac|linux)\b|\b(?:desktop|windows|mac|linux)\b.*(?:stable|extended stable)/i.test(v.title);
    if (spec.source === 'ubuntu') return /\b(?:chromium(?:-browser)?|firefox|git|openssh|openssl|sudo|curl|python[\d.]*|nodejs|docker(?:\.io)?|linux(?: kernel)?)\b/i.test(`${v.title} ${v.summary}`);
    if (spec.source.startsWith('release:')) return /\b(?:security|CVE|GHSA|vulnerabilit(?:y|ies))\b/i.test(`${v.title} ${v.summary}`);
    return true;
  }).map(v => {
    const time = Date.parse(v.published);
    if (!v.id || !v.title || !Number.isFinite(time) || !/^https:\/\//.test(v.url)) throw Error('Invalid feed entry');
    return { source: spec.source, id: v.id, title: v.title, url: v.url, published: new Date(time).toISOString(), summary: plainText(v.summary).slice(0, 500) };
  });
}

// A one-day overlap catches date-only KEV additions and delayed feed entries without repeats.
// Each source advances independently; a failed source retains its previous cursor.
export function selectNew(entries, previous, now) {
  const cutoff = previous ? Date.parse(previous.through) - DAY : now.getTime() - 3 * DAY;
  const seen = new Set(previous?.seen ?? []);
  return entries.filter(v => Date.parse(v.published) >= cutoff && Date.parse(v.published) <= now.getTime() && !seen.has(v.id));
}
export async function collect({ cursor = { sources: {} }, now = new Date(), fetchImpl = fetch, sources = SOURCES, token = process.env.GITHUB_TOKEN } = {}) {
  const nextCursor = structuredClone(cursor), items = [], sourceErrors = [];
  nextCursor.sources ??= {};
  await Promise.all(sources.map(async spec => {
    const signal = AbortSignal.timeout(20_000);
    try {
      const entries = [], headers = { 'User-Agent': 'molt-security-scout', Accept: spec.format === 'ghsa' ? 'application/vnd.github+json' : '*/*' };
      if (spec.format === 'ghsa' && token) headers.Authorization = `Bearer ${token}`;
      const previous = cursor.sources?.[spec.source];
      const cutoff = previous ? Date.parse(previous.through) - DAY : now.getTime() - 3 * DAY;
      let url = spec.url, pages = 0;
      while (url) {
        const response = await fetchImpl(url, { headers, signal, redirect: spec.format === 'ghsa' ? 'error' : 'follow' });
        if (!response.ok) throw Error(`HTTP ${response.status}`);
        const body = await response.text();
        entries.push(...parseSource(spec, body));
        url = null;
        if (spec.format === 'ghsa') {
          const raw = JSON.parse(body);
          const next = response.headers.get('link')?.match(/<([^>]+)>;\s*rel="next"/)?.[1];
          if (next && raw.length && raw.some(v => Date.parse(v.published_at) >= cutoff)) {
            const parsed = new URL(next);
            if (parsed.origin !== 'https://api.github.com' || parsed.pathname !== '/advisories') throw Error('Unexpected pagination URL');
            url = parsed.href;
          }
        }
        if (++pages >= 100 && url) throw Error('Pagination limit');
      }
      items.push(...selectNew(entries, previous, now));
      nextCursor.sources[spec.source] = { through: now.toISOString(), seen: [...new Set(entries.filter(v => Date.parse(v.published) >= now.getTime() - DAY).map(v => v.id))] };
    } catch (error) {
      sourceErrors.push({ source: spec.source, reason: /^HTTP \d+$|^Pagination limit$|^Unexpected pagination URL$|^Invalid .*(?:feed|entry)$/.test(error.message) ? error.message : signal.aborted ? 'timeout' : 'fetch-or-parse-failed' });
    }
  }));
  return { items: items.sort((a, b) => a.published.localeCompare(b.published) || a.source.localeCompare(b.source) || a.id.localeCompare(b.id)), sourceErrors: sourceErrors.sort((a, b) => a.source.localeCompare(b.source)), nextCursor };
}
export function commitCursor(stateDir, cursor) { privateDir(stateDir); writeJson(path.join(stateDir, 'cursor.json'), cursor); }
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const stateDir = process.argv[2] || defaultStateDir();
  const result = await collect({ cursor: readJson(path.join(stateDir, 'cursor.json'), { sources: {} }) });
  // Collection never commits the cursor. The caller acknowledges a successful whole run.
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
