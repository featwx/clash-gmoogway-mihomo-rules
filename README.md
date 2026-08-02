# GMOogway rules for Mihomo / Clash Verge Rev

This project converts the three Shadowrocket modules from
[`GMOogway/shadowrocket-rules`](https://github.com/GMOogway/shadowrocket-rules)
into clean Mihomo `classical` text rule-providers.

Generated files:

- `rules/sr_direct.list`
- `rules/sr_proxy.list`
- `rules/sr_reject.list`

Current converted totals:

- DIRECT: 111,907 Mihomo rules
- PROXY: 27,022 Mihomo rules
- REJECT: 171,066 Mihomo rules

The upstream modules currently contain 160 Shadowrocket-only rules that Mihomo
cannot represent (`URL-REGEX` and `USER-AGENT`). They are intentionally skipped
and recorded in `reports/skipped.json`; all other supported rules are retained.

The scheduled GitHub Actions workflow checks upstream every six hours. It strips
the Shadowrocket module header and policy column, adds `no-resolve` to IP CIDR
rules, removes duplicates, and reports rule types that Mihomo cannot represent.

The converted rule data remains subject to the upstream GNU GPL v3 license.
The original project and publisher attribution are retained in every output.

## Clash Verge Rev additive script

`GMOogway-规则增强-DNS防泄漏.js` is designed to run after an existing YaNet
global script. It leaves all proxies and proxy groups byte-for-byte unchanged.
It adds only these routing rules before the generic YaNet fallbacks:

1. REJECT -> existing `拒绝`
2. PROXY -> existing `其他外网`
3. DIRECT -> existing `直连`

The order is deliberate. The source lists contain overlapping domains; reject
rules must win over tracker/ad overlaps, and explicit proxy exceptions must win
over broad direct suffixes. The full audit is in `reports/audit.json`.

The DNS hardening keeps the existing groups and adds the documented Mihomo
pattern of TUN DNS hijacking plus `strict-route`, rule-mode Fake-IP, encrypted
domestic DNS for direct/node lookups, and encrypted foreign DNS explicitly sent
through the existing `其他外网` group. `prefer-h3` is disabled because Mihomo
does not recommend combining it with `respect-rules`.
