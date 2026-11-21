#!/usr/bin/env node
// safe-send 自测：零依赖，只用 Node 内置模块（需要 Node 18+）。
// 用法：
//   node test/run-tests.js                       # 测试 ../index.html
//   node test/run-tests.js --expect-tip 0xAbC…   # 另外断言 TIP_ADDRESS 恰好等于这个地址（上线前必跑）
// 原理：把 index.html 里的 <script> 取出来，配一个最小的假 DOM 运行，然后直接调用页面里的函数。
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const args = process.argv.slice(2);
const flag = (k) => { const i = args.indexOf(k); return i >= 0 ? args[i + 1] : undefined; };
const HTML_PATH = flag('--html') || path.join(__dirname, '..', 'index.html');
const EXPECT_TIP = flag('--expect-tip');
const HTML = fs.readFileSync(HTML_PATH, 'utf8');

/* ---------------- 加载器 ---------------- */
function load(opts = {}) {
  let src = HTML.slice(HTML.indexOf('<script>') + 8, HTML.lastIndexOf('</script>'));
  if (opts.tip !== undefined) {
    const re = /const TIP_ADDRESS = "[^"]*";/;
    if (!re.test(src)) throw new Error('找不到 TIP_ADDRESS 配置行');
    src = src.replace(re, `const TIP_ADDRESS = ${JSON.stringify(opts.tip)};`);
  }
  for (const [k, name] of [['sol', 'TIP_SOL'], ['btc', 'TIP_BTC']]) {
    if (opts[k] === undefined) continue;
    const re = new RegExp(`const ${name} = "[^"]*";`);
    if (!re.test(src)) throw new Error(`找不到 ${name} 配置行`);
    src = src.replace(re, `const ${name} = ${JSON.stringify(opts[k])};`);
  }
  if (opts.sha3) src = src.replace('p[bytes.length] ^= 0x01', 'p[bytes.length] ^= 0x06');
  const els = {};
  function mk(tag, id) {
    const e = {
      tag, id, children: [], _cls: new Set(), style: {}, value: '', textContent: '', href: '#', checked: false, listeners: {},
      get className() { return [...this._cls].join(' '); }, set className(v) { this._cls = new Set(String(v).split(/\s+/).filter(Boolean)); },
      appendChild(c) { this.children.push(c); return c; },
      addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); },
      replaceWith(n) { if (this.id) { n.id = this.id; els[this.id] = n; } },
      select() {}, remove() {},
      set innerHTML(v) { this._html = v; if (v === '') this.children = []; }, get innerHTML() { return this._html || ''; },
    };
    e.classList = { add: (c) => e._cls.add(c), remove: (c) => e._cls.delete(c), contains: (c) => e._cls.has(c) };
    return e;
  }
  for (const m of HTML.matchAll(/id="([^"]+)"/g)) els[m[1]] = mk('x', m[1]);
  const document = {
    getElementById: (id) => els[id] || null, createElement: (t) => mk(t), querySelectorAll: () => [], querySelector: () => (opts.recip ? { value: opts.recip } : null),
    body: mk('body'), execCommand: () => true, createTextNode: (t) => ({ text: t }),
  };
  const errors = [];
  const fakeConsole = { log() {}, warn() {}, error: (...a) => errors.push(a.join(' ')) };
  const names = 'detect,crossCheck,verdictOf,comparePoison,sha256,keccak256,eip55,segwitDecode,b58decode,checksumOk,crc16xmodem,KNOWN,NET,NETS,TIP_ADDRESS,TIP_SOL,TIP_BTC,tipAddressProblem,altTipProblem,setupTip,updateTicket,updateCheck';
  const fn = new Function('document', 'window', 'navigator', 'atob', 'TextEncoder', 'console', src + `\n;return {${names}};`);
  const api = fn(document, { isSecureContext: false }, {}, atob, TextEncoder, fakeConsole);
  api.els = els; api.errors = errors;
  return api;
}

/* ---------------- 断言 ---------------- */
let pass = 0, fail = 0; const fails = [];
function ok(cond, name, extra) { if (cond) pass++; else { fail++; fails.push(name + (extra !== undefined ? '  :: ' + extra : '')); } }
const hex = (u8) => Buffer.from(u8).toString('hex');
const section = (s) => console.log('· ' + s);

/* ---------------- 独立的参考实现（只用 node crypto） ---------------- */
const BTC58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const XRP58 = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';
function b58enc(buf, alpha) { let x = BigInt('0x' + (buf.length ? Buffer.from(buf).toString('hex') : '0')); let s = ''; while (x > 0n) { s = alpha[Number(x % 58n)] + s; x /= 58n; } for (const b of buf) { if (b === 0) s = alpha[0] + s; else break; } return s; }
function b58decRef(s, alpha) { let x = 0n; for (const c of s) { const i = alpha.indexOf(c); if (i < 0) return null; x = x * 58n + BigInt(i); } let h = x === 0n ? '' : x.toString(16); if (h.length % 2) h = '0' + h; let lead = 0; while (s[lead] === alpha[0]) lead++; return Buffer.concat([Buffer.alloc(lead), Buffer.from(h, 'hex')]); }
const dsha = (b) => crypto.createHash('sha256').update(crypto.createHash('sha256').update(b).digest()).digest();
function b58check(ver, payload, alpha) { const body = Buffer.concat([Buffer.from([ver]), payload]); return b58enc(Buffer.concat([body, dsha(body).subarray(0, 4)]), alpha); }
const CS32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function pm(v) { const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]; let c = 1; for (const x of v) { const t = c >>> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((t >>> i) & 1) c ^= G[i]; } return c >>> 0; }
const hx = (h) => [...h].map((c) => c.charCodeAt(0) >> 5).concat([0], [...h].map((c) => c.charCodeAt(0) & 31));
function conv(data) { let acc = 0, bits = 0; const out = []; for (const b of data) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out.push((acc >> bits) & 31); } } if (bits) out.push((acc << (5 - bits)) & 31); return out; }
function segEnc(hrp, ver, prog) { const d = [ver].concat(conv(prog)); const k = ver === 0 ? 1 : 0x2bc830a3; const p = pm(hx(hrp).concat(d, [0, 0, 0, 0, 0, 0])) ^ k; const ch = []; for (let i = 0; i < 6; i++) ch.push((p >> (5 * (5 - i))) & 31); return hrp + '1' + d.concat(ch).map((x) => CS32[x]).join(''); }

const A = load();

/* ---------------- 1. 哈希与编码 ---------------- */
section('SHA-256 / Keccak-256 / EIP-55');
for (let n = 0; n < 300; n++) { const b = crypto.randomBytes(n); ok(hex(A.sha256(b)) === crypto.createHash('sha256').update(b).digest('hex'), 'sha256 len ' + n); }
ok(hex(A.keccak256(new Uint8Array(0))) === 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', 'keccak256("")');
ok(hex(A.keccak256(Buffer.from('abc'))) === '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45', 'keccak256("abc")');
{ const S3 = load({ sha3: true }); for (let n = 0; n < 420; n += 7) { const b = crypto.randomBytes(n); ok(hex(S3.keccak256(b)) === crypto.createHash('sha3-256').update(b).digest('hex'), 'sha3 变体对照 node len ' + n); } }
const EIP55 = ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359', '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', '0xaf88d065e77c8cC2239327C5EDb3A432268e5831', '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85',
  '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', '0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E', '0xdAC17F958D2ee523a2206206994597C13D831ec7', '0x55d398326f99059fF775485246999027B3197955'];
for (const a of EIP55) ok(A.eip55(a.slice(2).toLowerCase()) === a, 'eip55 ' + a);
ok(A.crc16xmodem(Buffer.from('123456789')) === 0x31c3, 'CRC-16/XMODEM 标准校验值');

/* ---------------- 2. 地址识别 ---------------- */
section('EVM');
const EVM = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const flipCase = (a, i) => a.slice(0, i) + (a[i] === a[i].toUpperCase() ? a[i].toLowerCase() : a[i].toUpperCase()) + a.slice(i + 1);
for (let i = 2; i < 42; i++) { if (!/[a-fA-F]/.test(EVM[i])) continue; const d = A.detect(flipCase(EVM, i)); ok(!d.valid && d.findings.some((f) => f.level === 'bad'), 'EIP-55 单字符大小写篡改 -> bad @' + i); }
{ const d = A.detect('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAee'); ok(!d.valid && d.findings.some((f) => f.level === 'bad'), 'EIP-55 改一个字符 -> bad'); }
{ const d = A.detect(EVM.toLowerCase()); ok(d.valid && d.findings.some((f) => f.level === 'warn'), '全小写 -> warn（无校验）'); }

section('base58check：TRON / BTC / LTC / DOGE');
const VERS = [[0x41, 'tron'], [0x00, 'btc'], [0x05, 'btc'], [0x30, 'ltc'], [0x32, 'ltc'], [0x1e, 'doge'], [0x16, 'doge']];
let mutTotal = 0, mutValid = 0;
for (const [v, fam] of VERS) for (let k = 0; k < 40; k++) {
  const addr = b58check(v, crypto.randomBytes(20), BTC58);
  const d = A.detect(addr); ok(d && d.fam === fam && d.valid, `b58 ver 0x${v.toString(16)} -> ${fam}`, addr);
  ok(A.crossCheck(d, fam, 'self', '').some((f) => f.level === 'ok'), `${fam} 网络匹配`);
  for (let i = 1; i < addr.length; i++) { // 每个位置换一个字符
    const r = BTC58[(BTC58.indexOf(addr[i]) + 1 + (k % 57)) % 58]; const m = addr.slice(0, i) + r + addr.slice(i + 1);
    mutTotal++; if (A.detect(m).valid) mutValid++;
  }
}
ok(mutValid === 0, `base58 单字符篡改 ${mutTotal} 次全部判为无效`, mutValid + ' 次被误判为有效');
for (const a of ['1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t']) ok(A.detect(a).valid, '已知地址 ' + a);
ok(A.detect('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa').findings.some((f) => f.level === 'info' && /BCH/.test(f.text)), 'BTC 传统地址提示 BCH/BSV 同形');

section('XRP');
ok(A.detect('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh').fam === 'xrp' && A.detect('rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh').valid, 'XRP 创世账户');
for (let k = 0; k < 60; k++) {
  const a = b58check(0, crypto.randomBytes(20), XRP58); const d = A.detect(a); ok(d.fam === 'xrp' && d.valid, 'XRP 随机地址', a);
  const i = 2 + (k % (a.length - 3)); const m = a.slice(0, i) + XRP58[(XRP58.indexOf(a[i]) + 1 + (k % 57)) % 58] + a.slice(i + 1); ok(m !== a && !A.detect(m).valid, 'XRP 篡改 -> 无效', m);
}

section('Solana / TON / bech32');
for (let k = 0; k < 40; k++) { const a = b58enc(crypto.randomBytes(32), BTC58); const d = A.detect(a); ok(d.fam === 'sol' && d.valid && d.findings.some((f) => f.level === 'warn'), 'Solana 随机地址（带无校验提醒）', a); }
for (const [a, want] of [['EQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM9c', true], ['EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2N', true], ['UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBI', true], ['EQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqB2M', false]]) { const d = A.detect(a); ok(d.fam === 'ton' && d.valid === want, 'TON ' + a); }
function tonAddr(tag, wc, h) { const b = Buffer.concat([Buffer.from([tag, wc & 0xff]), h]); const c = A.crc16xmodem(b); return Buffer.concat([b, Buffer.from([c >> 8, c & 0xff])]).toString('base64').replace(/\+/g, '-').replace(/\//g, '_'); }
for (let k = 0; k < 20; k++) { const h = crypto.randomBytes(32); for (const t of [0x11, 0x51]) ok(A.detect(tonAddr(t, 0, h)).valid, 'TON 生成 tag ' + t.toString(16)); ok(!A.detect(tonAddr(0x91, 0, h)).valid, 'TON 测试网拒绝'); }
// BIP173 / BIP350
for (const a of ['BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4', 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0']) { const d = A.detect(a); ok(d.valid && d.fam === 'btc', 'bech32 有效 ' + a); }
// 规范上合法、但尚未启用的版本：解码本身要通过，但页面必须提示别转
for (const a of ['bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y', 'BC1SW50QGDZ25J', 'bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs']) {
  ok(A.segwitDecode(a).ok, 'BIP350 有效向量可解码 ' + a); const d = A.detect(a); ok(!d.valid && d.findings.some((f) => f.level === 'bad'), '未启用的 SegWit 版本 -> bad ' + a);
}
for (const a of ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd', 'BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh',
  'bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4', 'BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R', 'bc1pw5dgrnzv', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav',
  'BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf', 'bc1gmk9yu', 'bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du', 'bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90']) ok(!A.detect(a).valid, 'bech32 无效 ' + a);
ok(!A.detect('tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7').valid, 'tb1 测试网拒绝');
for (let k = 0; k < 20; k++) {
  ok(A.detect(segEnc('bc', k % 2, crypto.randomBytes(k % 2 ? 32 : 20))).valid, 'bc1 生成地址有效');
  const l = A.detect(segEnc('ltc', 0, crypto.randomBytes(20))); ok(l.valid && l.fam === 'ltc', 'ltc1 生成地址有效');
  for (const hrp of ['bc1zzz', 'ltc1q', 'bc1q', 'bc1', 'ltc1']) { const f = segEnc(hrp, 0, crypto.randomBytes(20)); const d = A.detect(f); ok(!d.valid && d.findings.some((x) => x.level === 'bad'), `前缀伪造 hrp="${hrp}" -> bad`, f); }
}

section('不能收款的已知地址');
ok(b58check(0, Buffer.alloc(20), XRP58) === 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', 'XRP ACCOUNT_ZERO 字符串独立推导一致');
{ const one = Buffer.alloc(20); one[19] = 1; ok(b58check(0, one, XRP58) === 'rrrrrrrrrrrrrrrrrrrrBZbvji', 'XRP ACCOUNT_ONE 字符串独立推导一致'); }
ok(b58check(0x41, Buffer.alloc(20), BTC58) === 'T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb', 'TRON 0 地址独立推导一致');
ok(b58check(0x00, Buffer.alloc(20), BTC58) === '1111111111111111111114oLvT2', 'BTC 0 地址独立推导一致');
ok(b58enc(Buffer.alloc(32), BTC58) === '11111111111111111111111111111111', 'Solana 系统程序 = 32 个 0 字节');
for (const k of Object.keys(A.KNOWN)) {
  if (k.startsWith('r')) { const raw = b58decRef(k, XRP58); ok(raw && raw.length === 25 && dsha(raw.subarray(0, 21)).subarray(0, 4).equals(raw.subarray(21)), 'XRP 黑洞地址校验和正确 ' + k); }
  const d = A.detect(k); ok(d.findings.some((f) => f.level === 'bad'), 'KNOWN 地址被标红 ' + k);
  const d2 = A.detect(k.startsWith('0x') ? A.eip55(k.slice(2)) : k); ok(d2.findings.some((f) => f.level === 'bad'), 'KNOWN 地址（校验和写法）被标红 ' + k);
}

section('其他误贴');
ok(A.detect('0x' + 'ab'.repeat(32)).findings.some((f) => f.level === 'bad'), '64 位 hex（TXID/私钥）-> bad');
ok(A.detect(EVM + '​').findings.some((f) => f.level === 'bad'), '零宽字符 -> bad');
ok(A.detect('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeАed').findings.some((f) => f.level === 'bad'), '西里尔字母 -> bad');
ok(A.detect('vitalik.eth').findings[0].level === 'info', '域名 -> info');

/* ---------------- 3. 大标题（安全结论）---------------- */
section('大标题：不该出现「没发现问题」的情况');
const V = (addr, net, recip, memo = '') => { const d = A.detect(addr); return A.verdictOf(d.findings.concat(A.crossCheck(d, net, recip, memo))).lv; };
const TRON = b58check(0x41, crypto.randomBytes(20), BTC58), XRPA = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh', TONA = 'UQCD39VS5jcptHL8vMjEXrzGaRcCVYto7HUn4bpAOg8xqEBI';
const BTCA = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', SOLA = b58enc(crypto.randomBytes(32), BTC58);
// 审查报告点名的场景
ok(V(EVM, '', '') !== 'ok', '没选网络 -> 不能显示安全', V(EVM, '', ''));
ok(V(EVM, '', '') === 'gate', '没选网络 -> 提示先选网络');
ok(V(EVM, 'base', '') === 'warn', 'EVM 选了网络但没选收款方 -> warn');
ok(V(XRPA, 'xrp', '') === 'gate', 'XRP 没选收款方 -> 不能显示安全（Tag 还没查）');
for (const a of [EVM, TRON, BTCA, XRPA, TONA, SOLA]) for (const r of ['', 'self', 'exchange', 'other']) ok(V(a, 'memo_other', r) === 'bad', `「其他需要 Memo 的链」+ ${a.slice(0, 6)} (${r || '未选'}) -> bad`);
ok(V(EVM, 'tron', 'exchange') === 'bad', 'EVM 地址选 TRC20 -> bad');
ok(V(TRON, 'bsc', 'exchange') === 'bad', 'TRON 地址选 BEP20 -> bad');
ok(V(XRPA, 'xrp', 'exchange', '') === 'bad', 'XRP 充值交易所没填 Tag -> bad');
ok(V(XRPA, 'xrp', 'exchange', 'abc') === 'bad', 'XRP Tag 非数字 -> bad');
ok(V(EVM, 'base', 'exchange') === 'warn', 'EVM 充值交易所 -> warn（确认网络支持）');
// 应该放行的场景（避免只会报警的工具）
ok(V(EVM, 'base', 'self') === 'ok', 'EVM 自己钱包 + Base -> ok');
ok(V(TRON, 'tron', 'self') === 'ok', 'TRON 自己钱包 -> ok');
ok(V(XRPA, 'xrp', 'exchange', '12345') === 'ok', 'XRP 交易所 + 数字 Tag -> ok');
// 全组合性质测试：只要显示 ok，就必须满足所有前提
const SAMPLES = [EVM, EVM.toLowerCase(), '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAee', TRON, BTCA, '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', b58check(0x30, crypto.randomBytes(20), BTC58),
  b58check(0x1e, crypto.randomBytes(20), BTC58), XRPA, TONA, SOLA, segEnc('bc', 0, crypto.randomBytes(20)), segEnc('bc', 1, crypto.randomBytes(32)), segEnc('ltc', 0, crypto.randomBytes(20)),
  segEnc('bc1zzz', 0, crypto.randomBytes(20)), 'bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs', 'vitalik.eth', 'hello', '0:' + 'a'.repeat(64), ...Object.keys(A.KNOWN)];
let combos = 0, okCount = 0;
for (const a of SAMPLES) for (const [netKey] of A.NETS) for (const r of ['', 'self', 'exchange', 'other']) for (const memo of ['', '123']) {
  combos++; const d = A.detect(a); const lv = V(a, netKey, r, memo);
  if (lv !== 'ok') continue; okCount++;
  const net = A.NET[netKey];
  const good = netKey && r && d.valid && d.fam === net.fam && !A.KNOWN[a] && !A.KNOWN[a.toLowerCase()] && !(net.memo && r === 'exchange' && !memo);
  ok(good, '显示 ok 但前提不满足', JSON.stringify({ a, netKey, r, memo, fam: d.fam, valid: d.valid }));
}
console.log(`  组合 ${combos} 个，其中显示「没发现问题」${okCount} 个，逐个核对前提`);

/* ---------------- 4. 打赏地址 ---------------- */
section('打赏地址（唯一配置）');
ok((HTML.match(/const TIP_ADDRESS = /g) || []).length === 1, 'TIP_ADDRESS 全文只定义一次');
{
  const rest = HTML.replace(/const TIP_ADDRESS = "[^"]*";/, '').replace(/function setupTip\(\)\{[\s\S]*?\n\}/, '');
  ok(!/TIP_ADDRESS/.test(rest), 'TIP_ADDRESS 只在定义处和 setupTip 里出现');
  ok((HTML.match(/0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913/gi) || []).length >= 1 && !/address=0x[0-9a-fA-F]{40}/.test(HTML), '页面里没有写死的收款地址链接');
}
const GOOD = '0xF6ec323b6b636111A32c9786d3786D30BD1D0c49';
const BAD_TIPS = { '': '空', '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAee': '校验和错误的手误', [GOOD.toLowerCase()]: '全小写', [GOOD.toUpperCase().replace('0X', '0x')]: '全大写',
  '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913': 'Base USDC 合约', '0x0000000000000000000000000000000000000000': '0 地址', '0x000000000000000000000000000000000000dEaD': '销毁地址',
  [' ' + GOOD]: '前导空格', [GOOD + '​']: '零宽字符', [GOOD.slice(0, 41)]: '少一位', '0x4200000000000000000000000000000000000006': 'WETH 合约', 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t': '非 EVM 地址' };
for (const [t, why] of Object.entries(BAD_TIPS)) {
  ok(A.tipAddressProblem(t) !== null, `tipAddressProblem 拒绝：${why}`);
  const P = load({ tip: t });
  ok(!P.els.tip.classList.contains('on'), `打赏区隐藏：${why}`);
  ok(['tip1', 'tip3', 'tip5'].every((id) => P.els[id].href === '#'), `没有付款链接：${why}`);
  ok(P.els.navTip.style.display !== '', `导航不显示打赏入口：${why}`);
  if (t) ok(P.errors.some((e) => /TIP_ADDRESS/.test(e)), `控制台报错提示：${why}`);
}
{
  ok(A.tipAddressProblem(GOOD) === null, 'f01 登记地址通过自检');
  const P = load({ tip: GOOD });
  ok(P.els.tip.classList.contains('on'), '合格地址 -> 显示打赏区');
  ok(P.els.navTip.style.display === '', '合格地址 -> 导航显示打赏入口');
  for (const n of [1, 3, 5]) ok(P.els['tip' + n].href === `ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453/transfer?address=${GOOD}&uint256=${n * 1000000}`, `EIP-681 链接 ${n} USDC`, P.els['tip' + n].href);
  const shown = P.els.tipChunks.children.map((c) => (c.children || []).map((x) => x.text || '').join('') || c.textContent).join('');
  ok(shown === GOOD, '分段显示的地址拼起来等于配置地址', shown);
}
// 当前文件里的实际配置
{
  const cur = A.TIP_ADDRESS;
  if (cur) { ok(A.tipAddressProblem(cur) === null, '当前 TIP_ADDRESS 通过自检', A.tipAddressProblem(cur)); ok(A.els.tip.classList.contains('on'), '当前配置下打赏区显示'); }
  else ok(!A.els.tip.classList.contains('on'), '当前未配置 -> 打赏区隐藏');
  if (EXPECT_TIP !== undefined) ok(cur === EXPECT_TIP, `TIP_ADDRESS 等于 --expect-tip`, `文件里是 "${cur}"，期望 "${EXPECT_TIP}"`);
  console.log(`  当前 TIP_ADDRESS = "${cur}"`);
}

// 备用地址（Solana / Bitcoin）
{
  const W = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '..', 'wallets.json'), 'utf8'));
  ok(A.TIP_SOL === '' || A.TIP_SOL === W.solana, 'TIP_SOL 等于 wallets.json 里的 solana 地址', A.TIP_SOL);
  ok(A.TIP_BTC === '' || A.TIP_BTC === W.bitcoin, 'TIP_BTC 等于 wallets.json 里的 bitcoin 地址', A.TIP_BTC);
  ok(A.altTipProblem(W.solana, 'sol') === null, '登记的 Solana 地址通过自检', A.altTipProblem(W.solana, 'sol'));
  ok(A.altTipProblem(W.bitcoin, 'btc') === null, '登记的 Bitcoin 地址通过自检', A.altTipProblem(W.bitcoin, 'btc'));
  const BAD_SOL = { '': '空', [' ' + W.solana]: '前导空格', [W.solana + '​']: '零宽字符', [W.solana.slice(0, -1) + '0']: '含非 base58 字符', [W.solana.slice(0, 20)]: '太短', '11111111111111111111111111111111': 'System Program', [GOOD]: 'EVM 地址', [W.bitcoin]: '比特币地址' };
  for (const [t, why] of Object.entries(BAD_SOL)) ok(A.altTipProblem(t, 'sol') !== null, `Solana 备用地址拒绝：${why}`);
  const flip = (s, i) => s.slice(0, i) + (s[i] === 'q' ? 'p' : 'q') + s.slice(i + 1);
  const BAD_BTC = { '': '空', [flip(W.bitcoin, 20)]: 'bech32 校验错误', [W.bitcoin.toUpperCase()]: '全大写（显示不一致）', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2': '旧格式（P2PKH）', [W.solana]: 'Solana 地址', [GOOD]: 'EVM 地址', [W.bitcoin + ' ']: '尾随空格' };
  for (const [t, why] of Object.entries(BAD_BTC)) ok(A.altTipProblem(t, 'btc') !== null, `Bitcoin 备用地址拒绝：${why}`);
  ok(A.altTipProblem(W.solana, 'evm') !== null, '不认识的链族一律拒绝');
  const chunkText = (el) => el.children.map((c) => (c.children || []).map((x) => x.text || '').join('') || c.textContent).join('');
  { const P = load({ tip: GOOD, sol: W.solana, btc: W.bitcoin });
    ok(P.els.tipMore.style.display === '' && P.els.tipSolWrap.style.display === '' && P.els.tipBtcWrap.style.display === '', 'EVM 合格 + 备用地址合格 -> 显示备用地址');
    ok(chunkText(P.els.tipSolChunks) === W.solana && chunkText(P.els.tipBtcChunks) === W.bitcoin, '备用地址分段拼起来等于配置'); }
  { const P = load({ tip: '', sol: W.solana, btc: W.bitcoin });
    ok(P.els.tipMore.style.display !== '' && !P.els.tip.classList.contains('on'), 'EVM 未配置 -> 备用地址也不显示'); }
  { const P = load({ tip: GOOD, sol: '', btc: flip(W.bitcoin, 20) });
    ok(P.els.tipMore.style.display !== '' && P.els.tipBtcWrap.style.display !== '', '备用地址都不合格 -> 折叠区隐藏');
    ok(P.errors.some((e) => /备用打赏地址（btc）/.test(e)), '不合格的备用地址在控制台报错'); }
  { const P = load({ tip: GOOD, sol: W.solana, btc: '' });
    ok(P.els.tipMore.style.display === '' && P.els.tipSolWrap.style.display === '' && P.els.tipBtcWrap.style.display !== '', '只配 Solana -> 只显示 Solana'); }
  ok(!/TIP_SOL|TIP_BTC/.test(HTML.replace(/const TIP_(SOL|BTC) = "[^"]*";/g, '').replace(/function setupTip\(\)\{[\s\S]*?\n\}/, '')), '备用地址只在定义处和 setupTip 里出现');
  const allAddr = HTML.match(/\b(bc1[02-9ac-hj-np-z]{20,}|[1-9A-HJ-NP-Za-km-z]{43,44})\b/g) || [];
  ok(allAddr.every((x) => x === W.solana || x === W.bitcoin || x === 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'), '页面里没有其他写死的 Solana / BTC 收款地址', allAddr.join(','));
}
ok(['tipMore', 'tipSolWrap', 'tipBtcWrap'].every((id) => new RegExp(`id="${id}" style="display:none"`).test(HTML)) && /section id="tip" class="tipbox"/.test(HTML), '打赏区和备用地址在 HTML 里默认隐藏（脚本校验通过才显示）');
// 「用 ① 检查这个地址」：填进 ① 并选 Base
{
  const P = load({ tip: GOOD });
  const h = (P.els.tipCheck.listeners.click || [])[0];
  ok(typeof h === 'function', '「用 ① 检查」按钮已绑定');
  if (h) { h(); ok(P.els.addr.value === GOOD && P.els.net.value === 'base', '点击后地址填入 ①，网络选 Base'); ok(P.els.result.children.length > 0, '点击后立即给出检查结果'); }
}

// 检查结果为 ✅ 时才出现一句打赏提示；未配置地址时从不出现
{
  const tipNote = (P) => P.els.result.children.some((c) => /#tip/.test(c.innerHTML || ''));
  const run = (tip, recip, addr, net) => { const P = load({ tip, recip }); P.els.addr.value = addr; P.els.net.value = net; P.updateCheck(); return P; };
  ok(tipNote(run(GOOD, 'self', EVM, 'base')), '✅ 结果下出现打赏提示');
  ok(!tipNote(run(GOOD, 'exchange', EVM, 'base')), '⚠️ 结果下不出现打赏提示');
  ok(!tipNote(run(GOOD, 'self', EVM, '')), '没选网络时不出现打赏提示');
  ok(!tipNote(run('', 'self', EVM, 'base')), '未配置地址时不出现打赏提示');
}

/* ---------------- 5. 防投毒 / 工单 / 文案 ---------------- */
section('防投毒比对 / 工单模板 / 文案');
ok(A.comparePoison(EVM, EVM.toLowerCase()).same, 'EVM 大小写不同视为同一地址');
{ const fake = EVM.slice(0, 8) + 'f'.repeat(26) + EVM.slice(-8); const r = A.comparePoison(EVM, fake); ok(!r.same && r.poison, '头尾相同中间不同 -> 投毒'); }
ok(!A.comparePoison(EVM, EVM + '​').same, 'B 带零宽字符 -> 不一致');
{
  const T = load(); T.updateTicket(); const out0 = T.els.t_out.value;
  ok(!/截图已附上|screenshot of the outgoing transfer is attached/.test(out0) && !/已显示成功|shows as successful/.test(out0), '工单默认不替用户声称已附截图 / 已查到交易');
  T.els.t_shot.checked = true; T.els.t_seen.checked = true; T.updateTicket(); const out1 = T.els.t_out.value;
  ok(/截图已附上/.test(out1) && /已显示成功/.test(out1) && /attached/.test(out1) && /successful/.test(out1), '勾选后才写入');
}
ok(!/人工审核/.test(HTML), '页面不再声称「人工审核」');
ok(/未经独立安全审计/.test(HTML), '页面写明未经独立安全审计');
ok(/default-src 'none'/.test(HTML), 'CSP 禁止一切网络请求');
ok(!/<script[^>]+src=/i.test(HTML) && ![...HTML.matchAll(/<link[^>]*>/gi)].some((m) => /href=["']https?:/i.test(m[0]) && !/rel=["']canonical["']/i.test(m[0])), '没有外部脚本或样式（canonical 除外）');
ok(/<link rel="canonical" href="https:\/\/zcoldwater\.github\.io\/safe-send\/">/.test(HTML), 'canonical 指向线上网址');
{ const m = HTML.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/); let j = null; try { j = JSON.parse(m[1]); } catch (e) {} ok(j && j['@type'] === 'WebApplication' && j.url === 'https://zcoldwater.github.io/safe-send/', 'JSON-LD 是合法 JSON'); }
ok(HTML.indexOf('<script>') > HTML.indexOf('application/ld+json'), '加载器取到的是主脚本（JSON-LD 在前）');

console.log(`\nPASS ${pass}  FAIL ${fail}`);
for (const f of fails.slice(0, 50)) console.log('FAIL:', f);
process.exit(fail ? 1 : 0);
