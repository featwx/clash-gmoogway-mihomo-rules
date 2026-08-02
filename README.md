# GMOogway rules for Mihomo / Clash Verge Rev

This project converts the three Shadowrocket modules from
[`GMOogway/shadowrocket-rules`](https://github.com/GMOogway/shadowrocket-rules)
into clean Mihomo `classical` text rule-providers.

Generated files:

- `rules/sr_direct.list`
- `rules/sr_proxy.list`
- `rules/sr_reject.list`

The scheduled GitHub Actions workflow checks upstream every six hours. It strips
the Shadowrocket module header and policy column, adds `no-resolve` to IP CIDR
rules, removes duplicates, and reports rule types that Mihomo cannot represent.

The converted rule data remains subject to the upstream GNU GPL v3 license.
The original project and publisher attribution are retained in every output.
