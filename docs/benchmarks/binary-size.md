# Binary size benchmarks

ADR: [ADR-0007](../adr/0007-m2-footprint-budget.md)

## Measurement methodology

```bash
# Build stripped minimal binary for a musl target
cargo zigbuild --release --locked \
  --no-default-features --features minimal \
  --target aarch64-unknown-linux-musl \
  --bin mihomo
# Binary already stripped by profile (strip = true); on CI use llvm-strip for ELF.
wc -c < target/aarch64-unknown-linux-musl/release/mihomo
```

Release profile: `lto = fat, strip = true, codegen-units = 1, panic = abort, opt-level = "z"`
(panic=abort added in M2.E per ADR-0007 §3; opt-level=z + mimalloc added in M2.E final pass.)

Feature set measured:
- **default**: `cargo build --release` (`full` bundle: ss, trojan, vless, dns-server, all listeners)
- **minimal**: `--no-default-features --features minimal`
  (`ss + trojan + dns-server + listener-mixed`)

## Size budgets (ADR-0007 §2)

| Target | Feature set | Budget | Gate |
|--------|------------|--------|------|
| `aarch64-unknown-linux-musl` | minimal | ≤ 8 MiB (8,388,608 B) | **hard** (CI fails) |
| `mipsel-unknown-linux-musl` | minimal | ≤ 7 MiB (7,340,032 B) | **soft** (CI warns) |
| `x86_64-unknown-linux-musl` | minimal | — | informational |

## Measurements

### Final (M2.E complete: mimalloc + opt-level=z + panic=abort)

Measured 2026-04-18 on macOS/Apple Silicon cross-compiling with cargo-zigbuild + zig 0.15.2.
**Note:** macOS `strip` cannot process ELF binaries; sizes reflect the `strip = true`
profile setting applied during cross-compilation. Linux CI with zig 0.13.0 may differ
slightly (typically ±2%).

| Target | Feature set | Stripped size | Budget | Status |
|--------|------------|---------------|--------|--------|
| `aarch64-unknown-linux-musl` | default (full) | 6,371,432 B (~6.07 MiB) | ≤ 20 MiB | ✓ |
| `aarch64-unknown-linux-musl` | minimal | 6,272,040 B (~5.98 MiB) | ≤ 8 MiB | **✓ under budget** |
| `x86_64-unknown-linux-musl` | default (full) | 7,788,120 B (~7.43 MiB) | ≤ 20 MiB | ✓ |
| `x86_64-unknown-linux-musl` | minimal | 7,659,928 B (~7.31 MiB) | — | informational |
| `mipsel-unknown-linux-musl` | default (full) | not measured (no macOS rustup target) | ≤ 20 MiB | — |
| `mipsel-unknown-linux-musl` | minimal | not measured | ≤ 7 MiB | — |

### Minimal vs default delta

| Target | Default | Minimal | Saved | Notes |
|--------|---------|---------|-------|-------|
| `aarch64` | 6.07 MiB | 5.98 MiB | ~100 KB | vless + relay + h2/grpc/httpupgrade excluded |

### Historical progression (aarch64 minimal)

| Profile state | Size | vs 8 MiB budget |
|--------------|------|-----------------|
| panic=abort only | 9,987,832 B (~9.5 MiB) | –1.1 MiB over |
| + opt-level="z" + mimalloc | 6,272,040 B (~5.98 MiB) | **+2.0 MiB headroom** |

The ~3.5 MiB saving came primarily from opt-level="z" (code size optimisation) and
mimalloc replacing the musl system allocator (eliminates heavy glibc-emulation code).

## Analysis

The aarch64 minimal binary is now ~5.98 MiB — **2 MiB under the 8 MiB hard budget** (ADR-0007 §2).
All three levers (panic=abort, opt-level=z, mimalloc) are applied and shipped as part of M2.E.

**Perf impact of opt-level=z**: engineer-a validation of W1/W2/W5 criterion benchmarks
against ADR-0006 thresholds is pending. Size levers are committed; if any ADR-0006
threshold regresses, opt-level can be moved to a separate profile or reverted.
