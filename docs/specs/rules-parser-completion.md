# Spec: Rule parser completion (M1.D-1, M1.D-3, M1.D-6)

Status: Draft (pm 2026-04-11, awaiting architect review)
Owner: pm
Tracks roadmap items: **M1.D-1** (IN-PORT, DSCP, UID, SRC-GEOIP,
PROCESS-PATH), **M1.D-3** (IP-SUFFIX, IP-ASN), **M1.D-6**
(DOMAIN-WILDCARD).
Depends on: none (all rule types listed here use data already in
`Metadata` or extend the existing `ParserContext`).
Not covered by this spec:
- **M1.D-2 GEOSITE** — requires a separate geosite DB loader; own spec.
- **M1.D-4** IN-TYPE, IN-NAME, IN-USER — depend on M1.F-1 named listeners; deferred.
- **M1.D-5** rule-provider upgrade (inline, mrs, interval) — own spec.
- **M1.D-7** SUB-RULE — own spec.
Related gap-analysis rows: §3 rule table, rows for each type below.

## Motivation

Eight rule types appear in real Clash Meta subscription `rules:` lists
but silently fall through to the `unknown rule type: …` error branch
in `crates/mihomo-rules/src/parser.rs`. Configs that use them either
fail to load (if the config is strict) or silently misroute traffic
(if the parse error is logged and the rule is skipped). This is a
silent-misroute bug — Class A per ADR-0002 for any rule whose absence
causes traffic to bypass intended policy.

Most of the missing types are small: 10–30 LOC of implementation,
zero new dependencies. Bundling them avoids eight separate tiny PRs
while keeping the scope bounded — each rule type is independently
testable.

## Rule types in scope

### M1.D-1 (parser gaps — enum variants already exist)

| Rule type | Match field | Notes |
|-----------|------------|-------|
| `IN-PORT` | `Metadata.in_port` | Inbound listener port. Integer or range. |
| `DSCP` | `Metadata.dscp` | IP DSCP marking (6 bits, 0–63). |
| `UID` | `Metadata.uid` | Linux process UID. Linux-only; no-op on other platforms with a warn. |
| `SRC-GEOIP` | `Metadata.src_addr` (IP) | GeoIP lookup on source IP. Reuses GEOIP MaxMindDB reader. |
| `PROCESS-PATH` | `Metadata.process_path` | Full executable path. String prefix or exact match (see §PROCESS-PATH). |

### M1.D-3 (not yet in enum)

| Rule type | Match field | Notes |
|-----------|------------|-------|
| `IP-SUFFIX` | `Metadata.dst_addr` (IP) | Suffix match on binary IP representation. See §IP-SUFFIX. |
| `IP-ASN` | `Metadata.dst_addr` (IP) | AS number lookup. Requires ASN MaxMindDB reader. See §IP-ASN. |

### M1.D-6 (not yet in enum)

| Rule type | Match field | Notes |
|-----------|------------|-------|
| `DOMAIN-WILDCARD` | `Metadata.host` | Glob pattern match on domain name. See §DOMAIN-WILDCARD. |

## Per-rule design

### IN-PORT

Payload is a port number or a range: `8080` or `1000-2000`. Matches
`Metadata.in_port` (the port the connection arrived on, e.g. the
HTTP/SOCKS5/TProxy listener's port).

```
IN-PORT,8080,DIRECT
IN-PORT,1000-2000,PROXY
```

`Metadata.in_port` must be set by each listener at connection creation.
If `in_port` is 0 (not populated by the listener — legacy path), the
rule never matches. Document with a comment; do not hard-error.

Implementation: `InPortRule` struct in `crates/mihomo-rules/src/in_port.rs`.
Parse payload as `u16` or `u16-u16` range (two values, dash separator).
Invalid port or range → parse error.

Upstream reference: `rules/common/inport.go`.

### DSCP

Payload is an integer 0–63 representing the DSCP field in the IP
header.

```
DSCP,46,PROXY       # EF (Expedited Forwarding)
```

`Metadata.dscp` is populated by the TProxy listener (which has access
to the raw IP packet) but is `0` for HTTP/SOCKS5 listeners (which
receive TCP connections, not raw packets). The rule still matches if
`dscp == 0` and the payload is `0` — this is correct behaviour (a
packet with DSCP=0 is best-effort, which is the default).

**Open question for architect:** should HTTP/SOCKS5 listeners set
`dscp` to `None` (Option<u8>) so DSCP rules can distinguish "unknown"
from "explicitly zero"? My lean: yes — change `Metadata.dscp` from
`u8` to `Option<u8>`. `None` on non-TProxy paths; `DSCP,46` never
matches a `None` DSCP. See §Open questions #2.

Implementation: `DscpRule` struct in `crates/mihomo-rules/src/dscp.rs`.
Parse payload as `u8`, validate 0–63. Out-of-range → parse error.

Upstream reference: `rules/common/dscp.go`.

### UID

Payload is a Unix user ID (integer).

```
UID,1000,DIRECT
```

Linux-only. On non-Linux platforms:
- `Metadata.uid` is always `None`.
- Parsing `UID,1000,PROXY` succeeds (no parse error — the rule is
  valid config, just never matches on non-Linux).
- The rule's `match_metadata` returns `false` on non-Linux, always.
- A warn-once at parse time on non-Linux: `"UID rule is Linux-only;
  this rule will never match on the current platform"`. Class B per
  ADR-0002: user's traffic still routes correctly (rule skipped);
  they get a signal that the rule is a no-op.

`Metadata.uid: Option<u32>` — already present (or add it). Set by the
process-lookup mechanism (M0-3) on Linux. `None` if lookup failed or
platform is non-Linux.

Implementation: `UidRule` struct in `crates/mihomo-rules/src/uid.rs`.
`#[cfg(target_os = "linux")]` guard on the match logic. Parse succeeds
cross-platform; match is always false on non-Linux.

Upstream reference: `rules/common/uid.go`.

### SRC-GEOIP

Identical to GEOIP but matches the connection's source IP
(`Metadata.src_addr`) rather than the destination.

```
SRC-GEOIP,CN,DIRECT     # route domestic-source traffic directly
```

Reuses the same `Arc<MaxMindDB>` reader from `ParserContext.geoip`.
No new dependency. `no-resolve` option is not applicable (source IP
is always an IP, never a hostname — TProxy connections carry the real
client IP).

Implementation: `GeoIpRule` already exists; add a `src: bool` field
to distinguish `GEOIP` (dst) from `SRC-GEOIP` (src). Alternatively,
a thin `SrcGeoIpRule` wrapper. Engineer's choice; either is fine.

Upstream reference: `rules/common/geoip.go::Rule` (the `isSource` flag).

### PROCESS-PATH

Like `PROCESS-NAME` but matches the full executable path. Two match
modes depending on the payload:

- Payload containing no path separator: exact-match against the
  filename component only (same as PROCESS-NAME — treat as fallback
  for configs that mix the two types).
- Payload starting with `/`: prefix match against the full path.
  `PROCESS-PATH,/usr/local/bin,PROXY` matches any binary under
  `/usr/local/bin/`.
- Payload containing `*`: glob match against the full path.

Upstream Go mihomo uses simple string equality (`rule.payload ==
process.path`). We extend to prefix match because real configs use
`PROCESS-PATH,/Applications/Safari.app,PROXY` expecting path-prefix
semantics, not exact-binary-path match.

**Divergence from upstream** — upstream matches exact path string; we
match prefix if payload starts with `/`. Classification: Class B per
ADR-0002 — user gets same routing outcome if they specify the exact
binary path; the prefix extension is additive and more useful.
Document in the rule's implementation comment.

`Metadata.process_path: Option<String>` — set by process-lookup (M0-3).
If `None` (lookup failed or not supported), the rule never matches.
No warn at match time (we'd emit a warn on every packet).

Implementation: `ProcessPathRule` struct in
`crates/mihomo-rules/src/process_path.rs`. Reuse or refactor
`crates/mihomo-rules/src/process.rs` — the logic is nearly identical.

Upstream reference: `rules/common/process.go`.

### DOMAIN-WILDCARD

Payload is a glob pattern applied to `Metadata.host` (the domain name
before DNS resolution).

```
DOMAIN-WILDCARD,*.example.com,PROXY
DOMAIN-WILDCARD,*.*.example.com,PROXY
```

Semantics:
- `*` matches any sequence of non-dot characters within a single
  label (e.g. `*.example.com` matches `foo.example.com` but NOT
  `foo.bar.example.com`).
- Matching is case-insensitive (domain names are).

**No `?` single-character wildcard** — upstream Go mihomo does not
support it; neither do we (most users expect `*` to mean any-label).

Implementation: expand `*` to a regex `[^.]+` and compile once at
parse time (cache in the rule struct). Do not use the `glob` crate
— it matches filesystem paths with different semantics (e.g., `*`
matches `/` on some glob implementations). A two-regex lines in
`new()` is sufficient.

Upstream reference: `rules/common/domain_wildcard.go`.

Add `RuleType::DomainWildcard` to `mihomo-common/src/rule.rs`.

### IP-SUFFIX

Suffix match on the binary representation of the IP address. Payload
format: `addr/prefix_len`, but the mask is applied from the **right**
(least-significant bits), not the left. Equivalent to: "does the IP
address, after zeroing the top N bits, equal the payload address?"

Example: `IP-SUFFIX,1.0.0.0/8` matches any IP whose last 8 bits are
`0x01` (1.x.x.x backwards). In practice used for ISP suffix patterns.

**Concrete matching algorithm:**

```
mask = ((1 << prefix_len) - 1)   // bitmask for the least-significant bits
match = (ip_as_u32 & mask) == (payload_ip_as_u32 & mask)
```

For IPv6, the same logic applies on the 128-bit integer representation.

Parse format: same as `IP-CIDR` (`addr/len`), but the `addr` is
right-masked, not left-masked. The parse error message must be distinct
from IP-CIDR errors: `"invalid IP-SUFFIX: expected addr/prefix_len
where prefix_len ≤ 32 (IPv4) or 128 (IPv6)"`.

Add `RuleType::IpSuffix` to `mihomo-common/src/rule.rs`.
New file: `crates/mihomo-rules/src/ip_suffix.rs`.

**Open question for architect** — see §Open questions #1: upstream
Go mihomo's implementation of `IP-SUFFIX` (confirm the right-mask
semantics above vs. any alternative interpretation I may have missed).

Upstream reference: `rules/common/ipcidr.go` (IP-SUFFIX branch there,
or a separate file — verify at implementation time).

### IP-ASN

Matches if the destination IP's Autonomous System Number equals the
payload integer.

```
IP-ASN,13335,PROXY     # Cloudflare ASN
```

Requires a **separate** GeoLite2-ASN MaxMindDB file
(`GeoLite2-ASN.mmdb`), distinct from the country MMDB used by GEOIP.
The ASN DB maps IP → `{ autonomous_system_number: u32,
autonomous_system_organization: String }`.

`ParserContext` grows an optional `asn` reader field:

```rust
pub struct ParserContext {
    pub geoip: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    pub asn: Option<Arc<maxminddb::Reader<Vec<u8>>>>,  // NEW
}
```

If `asn` is `None` and an `IP-ASN` rule is parsed, hard-error:
`"IP-ASN rule requires an ASN database (GeoLite2-ASN.mmdb); configure
'geo-data.asn-path' in dns: or top-level config"`. Class A per
ADR-0002: silently skipping the rule causes misrouting.

**Config field for ASN DB path** — needs a new top-level or
`geodata:` YAML field. Suggest `geodata-path` or `asn-db-path`.
Engineer: follow the same pattern as the GEOIP DB path. Flag as
**open question #3** for architect.

Add `RuleType::IpAsn` to `mihomo-common/src/rule.rs`.
New file: `crates/mihomo-rules/src/ip_asn.rs`.

Upstream reference: `rules/common/ipasn.go`.

## Divergences from upstream

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Rule | Case | Class | Rationale |
|---|------|------|:-----:|-----------|
| 1 | `UID` | Parsed on non-Linux → always non-matching | B | Warn-once; no routing change. Same as upstream (UID rules are meaningless on macOS/Windows). |
| 2 | `PROCESS-PATH` | Prefix match when payload starts with `/` | B | User's exact-path config still works; prefix is additive extension. Upstream exact-match only. |
| 3 | `IP-ASN` | Missing ASN DB → hard-error | A | Silently skipping causes misrouting (ASN-gated traffic bypasses intended proxy). Class A. |
| 4 | `DOMAIN-WILDCARD` | No `?` wildcard support | B | Upstream does not support `?` either; this is a match, not a divergence. |
| 5 | Any of these rule types | Absent from parser → silently skipped today | A | The status quo is the bug. This spec fixes it. |

## Acceptance criteria

A PR implementing this spec must:

1. All eight rule types parse successfully from valid YAML/text.
2. `IN-PORT,8080,DIRECT` matches `Metadata{in_port: 8080}` and not
   `Metadata{in_port: 8081}`.
3. `IN-PORT,1000-2000,PROXY` matches any port in [1000, 2000]
   inclusive; rejects port 999 and port 2001.
4. `DSCP,46,PROXY` matches `Metadata{dscp: Some(46)}`; does not match
   `Metadata{dscp: Some(0)}` or `Metadata{dscp: None}`.
5. `UID,1000,DIRECT` never matches on non-Linux (returns false).
   Logs exactly one `warn!` at parse time on non-Linux.
6. `SRC-GEOIP,US,PROXY` matches when the source IP resolves to the
   US in the MaxMindDB. Requires GEOIP reader in ParserContext.
7. `PROCESS-PATH,/usr/bin/curl,DIRECT` matches `process_path =
   "/usr/bin/curl"` exactly and (extension) prefix-matches any path
   under `/usr/bin/`.
8. `DOMAIN-WILDCARD,*.example.com,PROXY` matches `foo.example.com`;
   does not match `foo.bar.example.com` (single-label wildcard).
   Case-insensitive: matches `FOO.EXAMPLE.COM`.
9. `IP-SUFFIX,1.0.0.0/8,PROXY` matches all IPs whose least significant
   8 bits are `0x01`.
10. `IP-ASN,13335,PROXY` matches a Cloudflare IP when ASN reader is
    present; hard-errors at parse time when ASN reader is absent.
11. `RuleType::DomainWildcard`, `RuleType::IpSuffix`, `RuleType::IpAsn`
    added to the enum in `mihomo-common/src/rule.rs`.
12. `parse_rule` in `mihomo-rules/src/parser.rs` dispatches all eight
    types; the `_ => Err("unknown rule type")` arm no longer fires for
    any of them.
13. `cargo test --test rules_test` passes with no regressions.

## Test plan (starting point — qa owns final shape)

**Unit (one test module per new rule file):**

*IN-PORT:*
- `in_port_exact_match` — payload `8080`, metadata `in_port: 8080` → true.
- `in_port_exact_no_match` — payload `8080`, metadata `in_port: 8081` → false.
- `in_port_range_matches_lower_bound` — payload `1000-2000`, port 1000 → true.
- `in_port_range_matches_upper_bound` — port 2000 → true.
- `in_port_range_rejects_outside` — port 999 → false, port 2001 → false.
- `in_port_invalid_payload_errors` — `"abc"` → parse error.
  Upstream: `rules/common/inport.go::NewInPort`. NOT panic on bad port string.
- `in_port_zero_in_metadata_never_matches_nonzero_rule` — `in_port: 0`
  (not set) vs `IN-PORT,8080` → false. NOT a match on zero.

*DSCP:*
- `dscp_match` — payload `46`, dscp `Some(46)` → true.
- `dscp_no_match` — payload `46`, dscp `Some(0)` → false.
- `dscp_none_metadata_never_matches` — dscp `None` → false.
  This is the HTTP/SOCKS5 case: DSCP unknown, rule should not fire.
- `dscp_out_of_range_payload_errors` — `"64"` → parse error (max 63).
  Upstream: `rules/common/dscp.go` validates 0–63.

*UID:*
- `uid_match_linux` — `#[cfg(target_os = "linux")]` only; payload `1000`,
  uid `Some(1000)` → true.
- `uid_none_metadata_no_match` — uid `None` → false (lookup failed).
- `uid_nonlinux_always_false` — `#[cfg(not(target_os = "linux"))]`;
  any metadata → false. Class B per ADR-0002. Upstream matches; we
  return false cross-platform.
- `uid_nonlinux_parse_warns_once` — parse on non-Linux emits exactly
  one `warn!`. NOT a parse error.

*SRC-GEOIP:*
- `src_geoip_matches_source_ip` — source IP known to be US in test
  fixture DB, payload `US` → true.
- `src_geoip_no_match` — source IP not in US → false.
- `src_geoip_missing_reader_errors_at_parse` — no reader in ctx →
  parse error. Class A per ADR-0002.
  Upstream: `rules/common/geoip.go::isSource` path.
  NOT a silent pass-through when reader absent.

*PROCESS-PATH:*
- `process_path_exact_match` — payload `/usr/bin/curl`, path
  `/usr/bin/curl` → true.
- `process_path_prefix_match` — payload `/usr/bin`, path
  `/usr/bin/curl` → true. Extension beyond upstream; Class B.
  Upstream: exact match only (`rules/common/process.go`).
  NOT exact-only in our impl.
- `process_path_no_match` — payload `/usr/bin`, path
  `/usr/local/bin/curl` → false.
- `process_path_none_metadata_no_match` — `process_path: None` → false.

*DOMAIN-WILDCARD:*
- `domain_wildcard_single_label` — pattern `*.example.com`, host
  `foo.example.com` → true.
- `domain_wildcard_no_match_multi_label` — pattern `*.example.com`,
  host `foo.bar.example.com` → false.
  NOT a match — `*` is single-label only.
  Upstream: `rules/common/domain_wildcard.go` same semantics.
- `domain_wildcard_case_insensitive` — pattern `*.EXAMPLE.COM`, host
  `foo.example.com` → true.
- `domain_wildcard_no_match_wrong_parent` — pattern `*.example.com`,
  host `foo.notexample.com` → false.

*IP-SUFFIX:*
- `ip_suffix_ipv4_match` — payload `1.0.0.0/8`, IP `8.8.8.1` → true
  (last 8 bits = 0x01).
- `ip_suffix_ipv4_no_match` — payload `1.0.0.0/8`, IP `8.8.8.2` → false.
- `ip_suffix_ipv6_match` — payload `::1/8`, IPv6 addr with last byte 1
  → true.
- `ip_suffix_invalid_payload_errors` — `"not-an-ip"` → parse error.

*IP-ASN:*
- `ip_asn_match` — Cloudflare IP (e.g. `1.1.1.1`), payload `13335`,
  fixture ASN DB → true. Upstream: `rules/common/ipasn.go`.
- `ip_asn_no_match` — Google IP `8.8.8.8`, payload `13335` → false.
- `ip_asn_missing_reader_hard_errors` — no reader in ctx → parse
  error. Class A per ADR-0002. NOT silent skip.
  Upstream: logs a warning and the rule never matches. We reject.

**Regression (`rules_test.rs` — existing integration suite):**

- Run the full 78-rule test suite with no regressions. This is the
  implied acceptance criterion for any rules/ change.
- Add fixture-based tests for each new rule type (at least 2 per type)
  to the existing `tests/rules_test.rs` integration file.

## Implementation checklist (for engineer handoff)

- [ ] Add `RuleType::DomainWildcard`, `RuleType::IpSuffix`,
      `RuleType::IpAsn` to `mihomo-common/src/rule.rs`.
- [ ] Implement new rule files in `crates/mihomo-rules/src/`:
      `in_port.rs`, `dscp.rs`, `uid.rs`, `src_geoip.rs` (or extend
      `geoip.rs`), `process_path.rs`, `domain_wildcard.rs`,
      `ip_suffix.rs`, `ip_asn.rs`.
- [ ] Wire all eight into `parse_rule` in `parser.rs`.
- [ ] Extend `ParserContext` with `asn: Option<Arc<maxminddb::Reader<Vec<u8>>>>`.
- [ ] Resolve §Open question #3 with architect (ASN DB config key)
      before wiring `IP-ASN` through `load_config`.
- [ ] Change `Metadata.dscp` to `Option<u8>` (pending architect
      sign-off on §Open question #2). Update all listener code that
      sets `dscp`.
- [ ] `#[cfg(target_os = "linux")]` guard on `uid.rs` match logic.
      Parse succeeds cross-platform; match returns false on non-Linux.
- [ ] Ensure existing 78 rules tests pass with no regressions.
- [ ] Update `docs/roadmap.md` M1.D-1, D-3, D-6 rows with merged PR link.

## Open questions (architect input requested)

1. **IP-SUFFIX semantics.** Confirm the right-mask interpretation
   (least-significant bits match) is correct. Upstream's
   `rules/common/ipcidr.go` or a dedicated file — I want to verify
   before speccing the byte-exact test vectors.

2. **`Metadata.dscp: Option<u8>` vs `u8`.** Current `Metadata` type —
   is `dscp` already present? If `u8`, should we change to `Option<u8>`
   so DSCP rules can distinguish "TProxy set DSCP=0" from "listener
   didn't set DSCP"? My lean: `Option<u8>` is cleaner and prevents
   false-matches from rules like `DSCP,0` on HTTP-listener traffic.

3. **ASN DB config path.** What top-level YAML key should the ASN
   database path live under? Options: `geodata.asn-path`,
   `asn-db-path`, folding into an existing `geodata-mode` / `geox-url`
   config section. My lean: `geodata.asn-path` alongside the
   country DB, since they're the same format from the same vendor
   (MaxMind). Gap-analysis §6 mentions `geodata-mode` and `geox-url`
   as missing keys — this might be the right time to add a minimal
   `geodata:` subsection.
