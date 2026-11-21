# 转账前 30 秒安全自检 · Safe-Send Check

A free, offline, single-file web tool that helps crypto newcomers (Chinese UI) catch the mistakes behind most lost-funds support tickets **before** they hit "Confirm".

**Live:** https://zcoldwater.github.io/safe-send/ · **新手问答 / Guides (zh):** https://zcoldwater.github.io/safe-send/guide/

中文简介：转账、提币前花 30 秒查一遍——识别地址属于哪条链、核对网络（TRC20 / ERC20 / BEP20 / Base / Solana）、防地址投毒、提醒漏填 Memo，附「转错了怎么办」。纯本地运行，不联网，免费开源。

## What it does

1. **Address check.** Paste an address and it tells you which chain it belongs to and whether it is well-formed:
   - EVM (Ethereum, BNB Smart Chain, Base, Arbitrum, OP, Polygon, Avalanche, …): EIP-55 checksum
   - TRON / Bitcoin legacy / Litecoin / Dogecoin: base58check
   - Bitcoin / Litecoin SegWit and Taproot: bech32 / bech32m (BIP173 / BIP350)
   - XRP: base58check with the Ripple alphabet
   - TON: user-friendly format with CRC16 checksum, bounceable vs non-bounceable
   - Solana: 32-byte base58 (warns that Solana has no checksum)
   - Flags hidden zero-width characters, look-alike non-ASCII letters, transaction hashes or private keys pasted by mistake, token contract / burn addresses, ENS-style names
2. **Network cross-check.** Compares the address against the network you are about to use, and gives recipient-specific warnings (exchange deposit address, own wallet, third party), including missing Memo / Destination Tag and gas-token reminders.
3. **Address-poisoning compare.** Character-by-character diff of a trusted address against the one you are about to send to; detects the "same head and tail, different middle" pattern.
4. **7-question pre-send checklist.**
5. **"I already sent it wrong" first-aid guide** (wrong network, missing memo, wallet not showing funds, sent to a contract, address poisoning, phishing approvals or leaked seed phrase).
6. **Bilingual (zh/en) support-ticket generator**, so users give support everything they need in one message.

## Guides (`guide/`, Chinese)

Static, script-free pages (CSP `default-src 'none'`) that answer the most common newcomer questions in more depth and link back to the tool:

- [USDT 转错链 / 选错网络了怎么办](https://zcoldwater.github.io/safe-send/guide/usdt-wrong-network.html) (sent on the wrong network)
- [充币忘填 Memo / Tag 怎么办](https://zcoldwater.github.io/safe-send/guide/forgot-memo.html) (missing memo / destination tag)
- [地址投毒是什么、怎么防](https://zcoldwater.github.io/safe-send/guide/address-poisoning.html) (address poisoning)
- [提币选哪个网络](https://zcoldwater.github.io/safe-send/guide/choose-network.html) (choosing a withdrawal network)
- [USDC 官方合约地址一览](https://zcoldwater.github.io/safe-send/guide/usdc-contract-addresses.html) (official USDC contracts, from Circle's docs)

The pages are generated from one source file so that facts stay consistent with the tool (e.g. the USDC table is tested to match the tool's table).

## Privacy

Everything runs locally in your browser. The page sets a Content-Security-Policy of `default-src 'none'`, so it **cannot** make network requests. No analytics, no cookies, no storage.

## Tips (optional)

The tip address is configured in exactly one place: `const TIP_ADDRESS = "…";` at the top of the `<script>` in `index.html`. When it is set, the page shows a tip box with EIP-681 links for USDC on Base (chain 8453, USDC contract `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`, 6 decimals).

The box stays hidden, with no payment link anywhere on the page, unless the address passes a self-check: `0x` + 40 hex characters, mixed case with a valid EIP-55 checksum, not a known token contract / zero / burn address. Anything else (empty, typo, all-lowercase, the USDC contract itself, `0x0…0`) keeps the box hidden and logs the reason to the browser console.

The same EVM address receives USDC / USDT on Base, Arbitrum One, OP Mainnet, Polygon PoS, BNB Smart Chain and Ethereum; the box says so and warns explicitly that **TRC20 (TRON) cannot be sent to a 0x address**. Optional Solana (`TIP_SOL`) and Bitcoin (`TIP_BTC`, bc1q only) addresses are shown in a collapsed section, only when the EVM address is valid and each passes the tool's own validator. A "check this address with ①" button fills the tip address into the checker. Tips unlock nothing; the wallet belongs to the AI-agent author project and all receipts are public on-chain. The repo's Sponsor button (`.github/FUNDING.yml`) points to the same tip box.

## Tests

```
node test/run-tests.js                     # Node 18+, no dependencies
node test/run-tests.js --expect-tip 0x…    # also assert TIP_ADDRESS is exactly this address
node test/site-tests.js                    # guides, sitemap, IndexNow key, FUNDING.yml, internal links
```

The script loads the page's own `<script>` with a tiny fake DOM and checks it against independent reference code built on Node's `crypto`:

- SHA-256 vs Node (300 lengths); Keccak-256 known vectors plus multi-block inputs (via the SHA3 padding variant vs Node's `sha3-256`); EIP-55 examples and Circle's USDC contracts; CRC-16/XMODEM check value.
- Randomly generated TRON / BTC / LTC / DOGE / XRP / Solana / TON / bech32 addresses are recognised; ~9,000 single-character base58 mutations are all rejected; BIP173/BIP350 vectors; bech32 strings with a forged prefix (e.g. `bc1zzz1…`) are rejected; not-yet-activated SegWit versions are flagged.
- Known "cannot receive" addresses (token contracts, zero/burn addresses, XRP black holes, the Solana system program) are flagged red; the XRP/TRON/BTC/Solana zero addresses are re-derived independently.
- The headline verdict: across ~5,000 combinations of address × network × recipient × memo, every "✅ no problems found" is checked to have a valid address of the selected network's family, a selected recipient, and a memo when an exchange deposit needs one. Specifically: no network selected, EVM without a recipient, an address that does not belong to the "other memo chains" option, or a domain name never shows ✅.
- Tip box: shown only for a valid checksummed address, with the exact EIP-681 links; hidden for 12 kinds of bad configuration. Solana / Bitcoin tip addresses must equal the registered wallets and are rejected for 15 kinds of bad input (whitespace, zero-width characters, wrong chain, legacy BTC format, bad bech32 checksum, the Solana system program, …).
- Site: every page has a strict CSP and a correct canonical URL; guide pages contain no scripts; every internal link and anchor resolves; the sitemap lists exactly the published pages; external links are limited to an allow-list.

## Search engines

`sitemap.xml` lists every page. `244be2be0b48cd70ddd788b32526e740.txt` is an [IndexNow](https://www.indexnow.org/documentation) key file (its content is the key, its directory `/safe-send/` is its scope), used once per content update to tell participating search engines which pages changed.

## Known limitations

- All EVM chains share the same `0x` address format, so the tool cannot know whether the recipient supports a given EVM network. It always tells the user to check.
- Bitcoin Cash / BSV legacy addresses look identical to Bitcoin legacy addresses; the tool says so but cannot tell them apart.
- Solana addresses have no checksum.

## Disclaimer

The tool checks formats and gives common-sense warnings. It cannot tell who owns an address or whether it can be trusted, and it does not replace your own verification.

Written by an AI agent ("阿岩"), organized around common exchange support tickets, and published by a human. It has **not** been independently security-audited. MIT License.
