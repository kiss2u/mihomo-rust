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

Release profile: `lto = fat, strip = true, codegen-units = 1, panic = abort`
(panic=abort added in M2.E per ADR-0007 §3.)

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

Measured 2026-04-18 on macOS/Apple Silicon cross-compiling with cargo-zigbuild + zig 0.15.2.
**Note:** macOS `strip` cannot process ELF binaries; sizes reflect the `strip = true`
profile setting applied during cross-compilation. Linux CI with zig 0.13.0 may differ
slightly (typically ±2%).

| Target | Feature set | Stripped size | Budget | Status |
|--------|------------|---------------|--------|--------|
| `aarch64-unknown-linux-musl` | default (full) | 10,268,936 B (~9.8 MiB) | ≤ 20 MiB | ✓ |
| `aarch64-unknown-linux-musl` | minimal | 9,987,832 B (~9.5 MiB) | ≤ 8 MiB | **over budget** |
| `x86_64-unknown-linux-musl` | default (full) | 12,125,096 B (~11.6 MiB) | ≤ 20 MiB | ✓ |
| `x86_64-unknown-linux-musl` | minimal | 11,795,296 B (~11.2 MiB) | — | informational |
| `mipsel-unknown-linux-musl` | default (full) | not measured (no macOS rustup target) | ≤ 20 MiB | — |
| `mipsel-unknown-linux-musl` | minimal | not measured | ≤ 7 MiB | — |

### Minimal vs default delta

| Target | Default | Minimal | Saved | Notes |
|--------|---------|---------|-------|-------|
| `aarch64` | 9.8 MiB | 9.5 MiB | ~300 KB | vless + relay + h2/grpc/httpupgrade excluded |

The ~300 KB saving from minimal confirms the feature gates are connected and LTO
eliminates the gated code. However the absolute minimal size (9.5 MiB) exceeds
the 8 MiB hard budget.

## Analysis: gap to budget

aarch64 minimal is ~1.5 MiB over the 8 MiB hard budget.

Known contributors not yet applied (per ADR-0007 and ADR-0008):
1. **mimalloc** (ADR-0008, Task #31): replacing the system allocator is expected
   to save ~0.5–1 MiB on musl targets where the system allocator pulls in heavy
   glibc-emulation code.
2. **opt-level = "z"**: optimising for size instead of speed (current: default "3")
   is expected to save ~0.5–1 MiB.
3. **hickory-server zombie dep** (`dns-server` feature): hickory-server is currently
   listed as optional but referenced via the `dns-server` feature in the minimal
   bundle. Auditing whether the dep is truly dead-code-eliminated under LTO would
   clarify its contribution.

Action for architect-2: if the post-mimalloc + opt-level-z numbers still exceed
8 MiB, the ADR-0007 §2 budget will need a §6 amendment to match observed reality.
The M2.E feature gate infrastructure is in place; the numbers are the falsifiable signal.
