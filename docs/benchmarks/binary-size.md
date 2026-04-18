# Binary size benchmarks

Status: placeholder — real measurements require musl cross-compile toolchain
(cargo-zigbuild + zig 0.13.0). Values below are pre-measurement estimates;
update after running the CI release job against a `v*` tag.

ADR: [ADR-0007](../adr/0007-m2-footprint-budget.md)

## Measurement methodology

```bash
# Build stripped minimal binary for a musl target
cargo zigbuild --release --locked \
  --no-default-features --features minimal \
  --target aarch64-unknown-linux-musl \
  --bin mihomo
llvm-strip target/aarch64-unknown-linux-musl/release/mihomo
ls -lh target/aarch64-unknown-linux-musl/release/mihomo
```

Feature set measured:
- **default**: `cargo build --release` (all features: ss, trojan, vless, grpc, h2, ...)
- **minimal**: `--no-default-features --features minimal`
  (`ss + trojan + dns-server + listener-mixed`)

## Size budgets (ADR-0007 §2)

| Target | Feature set | Budget | Gate |
|--------|------------|--------|------|
| `aarch64-unknown-linux-musl` | minimal | ≤ 8 MiB | **hard** (CI fails) |
| `mipsel-unknown-linux-musl` | minimal | ≤ 7 MiB | **soft** (CI warns) |
| `x86_64-unknown-linux-musl` | minimal | — | informational |

## Measurements

> Not yet recorded. Run the release CI or measure locally with the commands
> above and fill in this table.

| Target | Feature set | Stripped size | Date | Compiler |
|--------|------------|---------------|------|----------|
| `aarch64-unknown-linux-musl` | default | — | — | — |
| `aarch64-unknown-linux-musl` | minimal | — | — | — |
| `mipsel-unknown-linux-musl` | default | — | — | — |
| `mipsel-unknown-linux-musl` | minimal | — | — | — |
| `x86_64-unknown-linux-musl` | default | — | — | — |
| `x86_64-unknown-linux-musl` | minimal | — | — | — |

## Load-bearing deps gated by minimal build

Per ADR-0007 §Migration step 0, these are the deps excluded by
`--no-default-features --features minimal`:

| Dep | Feature gate | Excluded from minimal? |
|-----|-------------|----------------------|
| `shadowsocks` (crypto library) | `ss` | No — `ss` is in minimal |
| `hickory-server` (DNS server) | `dns-server` | No — included in minimal |
| `vless` adapter code | `vless` | **Yes** |
| `grpc`/`h2`/`httpupgrade` layers | transport features | **Yes** — via mihomo-transport |
| HTTP/SOCKS5 inbounds | `listener-http`, `listener-socks5` | **Yes** — but implied by `listener-mixed` |
| TProxy inbound | `listener-tproxy` | **Yes** |

The primary size saving in the minimal bundle vs. default is:
- Exclusion of vless adapter code
- Exclusion of gRPC/H2/HTTPUpgrade transport layers (from mihomo-transport)
