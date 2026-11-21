#!/usr/bin/env node
// 站点级自测（零依赖）：问答页、sitemap、IndexNow key、FUNDING.yml、内部链接。
// 用法：node test/site-tests.js
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SITE = 'https://zcoldwater.github.io/safe-send/';
let pass = 0, fail = 0; const fails = [];
const ok = (c, name, extra) => { if (c) pass++; else { fail++; fails.push(name + (extra !== undefined ? '  :: ' + extra : '')); } };
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

const guideFiles = fs.readdirSync(path.join(ROOT, 'guide')).filter((f) => f.endsWith('.html')).map((f) => 'guide/' + f);
const pages = ['index.html', ...guideFiles];
const urlOf = (p) => SITE + p.replace(/(^|\/)index\.html$/, '$1');
const idsOf = (html) => new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));

ok(guideFiles.length >= 6, '至少 6 个问答页（含目录页）', guideFiles.length);

for (const p of pages) {
  const html = read(p);
  ok(/^<!doctype html>/i.test(html), `${p}: doctype`);
  ok(/<html lang="zh-CN">/.test(html), `${p}: lang=zh-CN`);
  ok(/<meta name="viewport" content="width=device-width, initial-scale=1">/.test(html), `${p}: viewport`);
  ok(/http-equiv="Content-Security-Policy" content="default-src 'none';/.test(html), `${p}: CSP default-src 'none'`);
  const canon = (html.match(/<link rel="canonical" href="([^"]+)">/) || [])[1];
  ok(canon === urlOf(p), `${p}: canonical`, canon);
  const title = (html.match(/<title>([^<]+)<\/title>/) || [])[1] || '';
  ok(title.length >= 10 && title.length <= 90, `${p}: title 长度`, title.length);
  const desc = (html.match(/<meta name="description" content="([^"]+)">/) || [])[1] || '';
  ok(desc.length >= 40 && desc.length <= 200, `${p}: description 长度`, desc.length);
  ok((html.match(/<h1>/g) || []).length === 1, `${p}: 只有一个 h1`);
  ok(!/人工审核/.test(html), `${p}: 不声称「人工审核」`);
  ok(/未经独立(安全审计|审核)/.test(html), `${p}: 写明未经独立审核`);
  ok(/AI 代理/.test(html), `${p}: 写明 AI 代理编写`);
  if (p.startsWith('guide/')) {
    ok(!/<script/i.test(html), `${p}: 没有任何脚本`);
    ok(/href="\.\.\/"/.test(html), `${p}: 有回到工具的链接`);
    ok(!/0x[0-9a-fA-F]{40}/.test(html.replace(/<table>[\s\S]*?<\/table>/g, '')) || p.includes('usdc'), `${p}: 表格外没有写死的 0x 地址`);
  }
  // 外链白名单
  const ext = [...html.matchAll(/href="(https?:[^"]+)"/g)].map((m) => m[1]).filter((u) => u !== canon);
  const allowed = [/^https:\/\/developers\.circle\.com\//, /^https:\/\/github\.com\/zColdWater\/safe-send$/, /^https:\/\/zcoldwater\.github\.io\/safe-send\//, /^https:\/\/opensource\.org\/licenses\/MIT$/, /^https:\/\/zcoldwater\.github\.io\/funding-atlas\/$/, /^https:\/\/github\.com\/zColdWater\/web3-zh-kit$/];
  for (const u of ext) ok(allowed.some((r) => r.test(u)), `${p}: 外链在白名单内`, u);
  // 内部链接都能解析到文件，锚点存在
  for (const m of html.matchAll(/href="([^"#:]*)(#[^"]*)?"/g)) {
    const [, rel, hash] = m;
    if (rel === '' && !hash) continue;
    let target = rel === '' ? p : path.posix.normalize(path.posix.join(path.posix.dirname(p), rel));
    if (target === '.' || target.endsWith('/')) target = (target === '.' ? '' : target) + 'index.html';
    if (!target.endsWith('.html')) target += '/index.html';
    const exists = fs.existsSync(path.join(ROOT, target));
    ok(exists, `${p}: 内部链接 ${rel || ''}${hash || ''} -> ${target} 存在`);
    if (exists && hash && hash.length > 1) ok(idsOf(read(target)).has(hash.slice(1)), `${p}: 锚点 ${hash} 在 ${target} 里存在`);
  }
}

// 问答页之间互相链接（每页至少链到 4 个其他问答页）
for (const p of guideFiles.filter((f) => !f.endsWith('index.html'))) {
  const html = read(p);
  const n = guideFiles.filter((q) => q !== p && !q.endsWith('index.html') && html.includes(`href="${path.basename(q)}"`)).length;
  ok(n >= 4, `${p}: 链到其他问答页`, n);
}

// sitemap = 全部页面
{
  const xml = read('sitemap.xml');
  const locs = [...xml.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]);
  ok(/^<\?xml version="1.0" encoding="UTF-8"\?>/.test(xml) && /xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9"/.test(xml), 'sitemap 头部合法');
  const want = pages.map(urlOf).sort();
  ok(JSON.stringify([...locs].sort()) === JSON.stringify(want), 'sitemap 恰好列出全部页面', locs.join(' '));
  ok(locs.every((u) => u.startsWith(SITE)), 'sitemap 里的 URL 都在 /safe-send/ 之下（IndexNow key 作用范围）');
}

// IndexNow key 文件
{
  const keys = fs.readdirSync(ROOT).filter((f) => /^[A-Za-z0-9-]{8,128}\.txt$/.test(f));
  ok(keys.length === 1, '恰好一个 IndexNow key 文件', keys.join(','));
  if (keys[0]) ok(read(keys[0]) === keys[0].replace(/\.txt$/, ''), 'key 文件内容 = 文件名（不含换行）');
  ok(fs.existsSync(path.join(ROOT, '.nojekyll')), '.nojekyll 存在（让 Pages 原样发布）');
}

// FUNDING.yml
{
  const y = read('.github/FUNDING.yml');
  const m = y.match(/^custom: \["([^"]+)"\]\s*$/m);
  ok(m && m[1] === SITE + '#tip', 'FUNDING.yml custom 指向工具页打赏区', y);
  ok(idsOf(read('index.html')).has('tip'), '工具页有 #tip');
}

// 问答页里的 USDC 合约表 = 工具页里的表（同一来源，防止两处不一致）
{
  const rows = (html) => [...html.matchAll(/<tr><td>([^<]+)<\/td><td><code>([^<]+)<\/code><\/td><\/tr>/g)].map((m) => m[2]);
  const a = rows(read('index.html')), b = rows(read('guide/usdc-contract-addresses.html'));
  ok(a.length === 7 && JSON.stringify(a) === JSON.stringify(b), 'USDC 合约表两处一致', JSON.stringify(b));
}

// 问答页说法与工具一致的几个关键点
{
  const all = guideFiles.map(read).join('\n');
  ok(!/保证(找回|成功|收录)/.test(all.replace(/不保证(找回|成功|收录)?/g, '')), '没有「保证找回」之类的承诺');
  ok(/黑客找回|追回/.test(all) && /二次诈骗|都是骗子/.test(all), '提醒「找回服务」是诈骗');
}

console.log(`site-tests  PASS ${pass}  FAIL ${fail}`);
for (const f of fails.slice(0, 60)) console.log('FAIL:', f);
process.exit(fail ? 1 : 0);
