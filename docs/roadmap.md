# mihomo-rust Roadmap

Owner: pm
Last updated: 2026-04-11
Source inputs: `docs/vision.md`, `docs/gap-analysis.md`, `docs/ci-status.md`.

This roadmap translates the architect's gap analysis into an ordered work
program. Milestones mirror `docs/vision.md`; items inside each milestone are
ordered by **user-visible value per unit of risk**. Anything marked
*excluded* in `docs/vision.md` §Non-goals is intentionally absent.

Legend for each work item:

- **Value**: H/M/L — how many real subscriptions / deployments it unblocks.
- **Risk**: H/M/L — implementation complexity, crypto surface, or blast
  radius on the hot path.
- **Spec**: link to `docs/specs/<feature>.md` once drafted (PM owns).
- **Owner**: engineer handoff target.

---

## M0 — Correctness cleanup (do first, in parallel with M1)

Small, bounded items surfaced in `gap-analysis.md` §7. Each is a reliability
or security regression vs upstream; none needs a full spec. Engineer can
pick these up as "fix-it Fridays" while larger M1 specs are drafted.

| # | Item | Value | Risk | Notes |
|---|------|:-----:|:----:|-------|
| M0-1 | Enforce REST API `secret` (Bearer auth) | H | L | `AppState.secret` is `#[allow(dead_code)]`; unauth API is a security gap |
| M0-2 | Replace `eprintln!` debug in `routes.rs:115` with `tracing::debug!` | L | L | Hot-path log spam |
| M0-3 | Wire `PROCESS-NAME` lookup (netlink on Linux, `libproc` on macOS) | M | M | Currently a no-op `Box<dyn Fn()>`; rules silently never match |
| M0-4 | GEOIP parser + shared `Arc<MaxMindDB>` plumbing | H | M | Today `parse_rule` rejects `GEOIP`; YAML with GEOIP fails to load |
| M0-5 | Populate `Resolver` hosts trie from `dns.hosts` config | M | L | Trie allocated, never filled |
| M0-6 | Wire DNS in-flight dedup (`inflight: DashMap`) | M | L | Allocated but `#[allow(dead_code)]` |
| M0-7 | Verify `AND/OR/NOT` logic rules reachable from top-level parser | M | L | `logic.rs` exists; confirm dispatch, add tests |
| M0-8 | Prune dead `AdapterType` variants (or mark `#[doc(hidden)]`) | L | L | `RejectDrop`, `Compatible`, `Pass`, `Dns`, `Relay`, `LoadBalance`, unimplemented protos |
| M0-9 | Drop or implement `rule-providers.interval` periodic refresh | M | L | Field accepted and ignored today |
| M0-10 | CI P0: wire `v2ray_plugin_integration` + `pre_resolve_test` into `test.yml` | H | L | Tests exist but are not gated (see `ci-status.md` §Gaps P0) |

Exit criteria: every item closed or converted into a tracked issue with a
clear decision (implement / defer / remove).

---

## M1 — Parity for the common user

Goal from `vision.md`: a typical Clash Meta user's subscription loads and
routes correctly on mihomo-rust. Priority is breadth over polish.

### M1.A — Reusable transports (prereq)

Before VMess/VLESS land we need transports as composable layers, not
bespoke code glued into a single adapter. Today `ws` and `tls` live inside
`v2ray_plugin.rs` / `trojan.rs`. Architecture is settled in
[ADR-0001](adr/0001-mihomo-transport-crate.md): new `mihomo-transport`
leaf crate; `Transport` trait with `connect(Box<dyn Stream>) -> Box<dyn
Stream>`; five initial layers (tls / ws / grpc / h2 / httpupgrade), each
behind a Cargo feature.

**gRPC decision (2026-04-11):** hand-roll the "gun" framing on top of the
`h2` crate — **no tonic, no prost**. Upstream `transport/gun/gun.go` has
no protobuf schema; "gRPC transport" is just HTTP/2 tunnelling with a
fake `content-type: application/grpc` header. Tonic would pull ~30
crates for zero code-gen value.

**Engineer build sequence** (baked into ADR-0001 §Build sequence — specs
below must not reorder without architect sign-off):

1. M1.A-1 — crate skeleton + `Transport` trait + `tls` layer; migrate `trojan.rs`.
2. M1.A-2 — `ws` layer (with early-data header); migrate `v2ray_plugin.rs`.
3. **VMess (M1.B-1) unblocks here** — only needs `tls + ws`.
4. M1.A-3 — `grpc` (hand-rolled gun) layer.
5. M1.A-4 — `h2` + `httpupgrade` layers.

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.A-1 | `mihomo-transport` crate skeleton + `Transport` trait + `tls` layer + `trojan.rs` migration | H | M | [`docs/specs/transport-layer.md`](specs/transport-layer.md) *(draft)* | engineer |
| M1.A-2 | `ws` layer + `v2ray_plugin.rs` migration (same spec) | H | M | same spec, §M1.A-2 | engineer |
| M1.A-3 | `grpc` (hand-rolled gun over `h2`) layer (same spec) | H | M | same spec, §M1.A-3 | engineer |
| M1.A-4 | `h2` + `httpupgrade` layers (same spec) | M | M | same spec, §M1.A-4 | engineer |

All four steps are covered by a single spec (`docs/specs/transport-layer.md`)
because ADR-0001 already settled the architecture — the spec only fills in
YAML schema, struct shapes, error types, and per-layer tests.

### M1.B — Outbound protocols

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.B-1 | VMess outbound (AEAD, legacy MD5 auth behind feature flag) | H | H | [`docs/specs/proxy-vmess.md`](specs/proxy-vmess.md) *(draft)* | engineer |
| M1.B-2 | VLESS outbound (plain, XTLS-vision optional) | H | H | [`docs/specs/proxy-vless.md`](specs/proxy-vless.md) *(draft)* | engineer |
| M1.B-3 | HTTP CONNECT outbound | M | L | small — fold into a single spec with M1.B-4 | engineer |
| M1.B-4 | SOCKS5 outbound | M | L | `docs/specs/proxy-http-socks-outbound.md` *(todo)* | engineer |

**Deferred to M1.5 / M2** (architect recommendation, 2026-04-11):

- **Hysteria2** — `quinn` pulls a sizable QUIC dep tree; footprint goal in
  `vision.md` makes it a poor fit for M1. Revisit after the M2 footprint
  audit so we know the cost. Same logic applies to TUIC and any other
  QUIC-based protocol.
- **Reality transport** (pairs with VLESS but is its own large spec).
- **WireGuard, Snell, SSH** — niche/legacy.

### M1.C — Proxy groups

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.C-1 | `load-balance` group (round-robin + consistent-hash strategies) | H | L | [`docs/specs/group-load-balance.md`](specs/group-load-balance.md) *(draft)* | engineer |
| M1.C-2 | `relay` group (chain multiple outbounds) | M | M | [`docs/specs/group-relay.md`](specs/group-relay.md) *(draft)* | engineer |

### M1.D — Rules & providers

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.D-1 | Finish parser for already-enum'd rule types: `IN-PORT`, `DSCP`, `UID`, `SRC-GEOIP`, `PROCESS-PATH` | M | L | [`docs/specs/rules-parser-completion.md`](specs/rules-parser-completion.md) *(draft)* | engineer |
| M1.D-2 | `GEOSITE` rule + geosite DB loader (**`mrs` only**, per architect 2026-04-11) | H | M | `docs/specs/rule-geosite.md` *(todo)* | engineer |
| M1.D-3 | `IP-SUFFIX`, `IP-ASN` (requires ASN MMDB) | M | M | bundled into M1.D-1 spec | engineer |
| M1.D-4 | `IN-TYPE`, `IN-NAME`, `IN-USER` (depends on named listeners — see M1.F) | M | M | defer until M1.F-1 | engineer |
| M1.D-5 | Rule provider `inline` type, `mrs` binary format, periodic `interval` refresh | M | M | `docs/specs/rule-provider-upgrade.md` *(todo)* — supersedes M0-9 if taken together | engineer |
| M1.D-6 | `DOMAIN-WILDCARD` | L | L | bundled into M1.D-1 spec | engineer |
| M1.D-7 | `SUB-RULE` (named rule subsets) | M | M | `docs/specs/sub-rules.md` *(todo)* | engineer |

### M1.E — DNS

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.E-1 | DoH and DoT upstream clients (hickory supports both) | H | M | [`docs/specs/dns-doh-dot.md`](specs/dns-doh-dot.md) *(draft)* | engineer |
| M1.E-2 | `default-nameserver` (bootstrap) | H | L | bundled into M1.E-1 spec | engineer |
| M1.E-3 | `nameserver-policy` (per-domain routing) | H | M | `docs/specs/dns-nameserver-policy.md` *(todo)* | engineer |
| M1.E-4 | `fallback-filter` (GeoIP / IP-CIDR / domain gating) | M | M | bundle with M1.E-3 | engineer |
| M1.E-5 | `hosts` + `use-system-hosts` | M | L | supersedes M0-5 if taken together | engineer |
| M1.E-6 | DoQ upstream | L | M | defer to M2 unless a user asks | engineer |

### M1.F — Inbounds & sniffer

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.F-1 | Generic `listeners:` named-listener config (prereq for IN-NAME / IN-TYPE) | M | M | `docs/specs/listeners-unified.md` *(todo)* | engineer |
| M1.F-2 | TLS SNI + HTTP Host sniffer (enables rule matching on port-only flows) | H | M | [`docs/specs/sniffer.md`](specs/sniffer.md) *(draft)* | engineer |
| M1.F-3 | `authentication` + `skip-auth-prefixes` + LAN ACLs | M | L | `docs/specs/inbound-auth-acl.md` *(todo)* | engineer |
| M1.F-4 | Linux `redir` listener (SO_ORIGINAL_DST) | L | M | defer to M1.x or M2 | — |
| M1.F-5 | Static `tunnel` listener (SS-style port→target) | L | L | defer | — |

### M1.G — REST API completeness (Clash Dashboard / Yacd compat)

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.G-1 | Bearer `secret` auth enforcement (= M0-1, tracked here too) | H | L | trivial, fold into M0-1 | engineer |
| M1.G-2 | `GET /proxies/:name/delay` and `GET /group/:name/delay` | H | L | [`docs/specs/api-delay-endpoints.md`](specs/api-delay-endpoints.md) *(draft)* | engineer |
| M1.G-3 | `GET /logs` websocket stream | H | M | `docs/specs/api-logs-websocket.md` *(todo)* | engineer |
| M1.G-4 | `GET /memory` websocket (runtime RSS stream) | M | L | bundle with M1.G-3 | engineer |
| M1.G-5 | `GET/PUT /providers/rules[/:name]` | M | L | depends on M1.D-5 | engineer |
| M1.G-6 | `GET/PUT /providers/proxies[/:name]` + proxy providers impl | H | M | depends on M1.H-1 | engineer |
| M1.G-7 | `DELETE /connections` (bulk) | L | L | trivial | engineer |
| M1.G-8 | `GET /dns/query` (align with upstream; current is POST) | L | L | additive; keep POST for back-compat | engineer |
| M1.G-9 | `POST /cache/dns/flush` | L | L | trivial | engineer |
| M1.G-10 | `PUT /configs` (reload from path/body) | M | M | `docs/specs/api-config-reload.md` *(todo)*; relates to M3 hot-reload | engineer |

### M1.H — Providers & observability

| # | Item | Value | Risk | Spec | Owner |
|---|------|:-----:|:----:|------|-------|
| M1.H-1 | `proxy-providers` (http/file, health-check, include-all) | H | M | [`docs/specs/proxy-providers.md`](specs/proxy-providers.md) *(draft)* | engineer |
| M1.H-2 | Prometheus `/metrics` (traffic, conns, rule-match counters, proxy health) | H | L | `docs/specs/metrics-prometheus.md` *(todo)* | engineer |
| M1.H-3 | Migration guide from Go mihomo (supported vs intentionally-not fields) | M | L | `docs/migration-from-go-mihomo.md` *(todo, PM)* | pm |

### M1 exit criteria (from `vision.md`)

A representative real-world Clash Meta subscription loads, routes traffic
correctly, and survives a 24-hour soak test without leaks or panics.

---

## M2 — Performance and footprint

Scope frozen after M1 lands. Placeholder order (all items from `vision.md`
§M2):

1. Benchmark harness vs Go mihomo on identical hardware — `docs/benchmarks/`.
2. Allocator audit of TCP relay and UDP NAT hot paths.
3. Cargo feature flags for every optional protocol/transport; minimal-build
   size budget for `aarch64-musl` and `mipsel-musl`.
4. Rule-engine micro-optimizations (trie layout, IP-CIDR structure).
5. Release CI — prebuilt static binaries per `ci-status.md` P1 item 5.
6. M2 also absorbs: MSRV pin, macOS CI job, `cargo audit` cron, `cargo doc`
   check, `cargo hack --feature-powerset`, coverage upload (`ci-status.md`
   §P1/P2).

Exit criteria: measurably lower CPU and RSS than Go mihomo on a shared
benchmark, minimal-build binary under stated size budget.

---

## M3 — Operational maturity

Scope per `vision.md` §M3. Specs drafted only after M2 exit:

- Hot config reload without dropping connections where safe.
- OpenTelemetry trace/metric export (opt-in).
- `mihomo check` CLI with actionable errors + schema export.
- Subscription robustness: retry/backoff, signed subscriptions.
- API auth hardening: per-endpoint authz, audit log for mutating calls.
- Documented config-compat policy across releases.

---

## How this doc is maintained

- PM owns ordering, value/risk grades, and the "spec exists yet?" column.
- Adding a new item requires a one-line justification in the PR that
  updates this file.
- When an item lands, strike it through and link the merged PR; do not
  delete rows until the next milestone rollover — the history is useful.
- Items move *between* milestones only on architect or team-lead sign-off.
- Scope changes that reintroduce a `vision.md` §Non-goals item require
  explicit product approval in the commit message.
