/// UDP NAT fast-path benchmark
///
/// Isolates the allocation at `udp.rs:30`:
///     let key = format!("{}:{}", src, metadata.remote_address());
///
/// This String is allocated on **every** incoming UDP packet, including the
/// hot path (existing session lookup). Task #31 (allocator audit) will fix
/// this; this bench establishes the pre-fix baseline and will measure the
/// post-fix improvement.
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use mihomo_common::Metadata;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

fn make_src() -> SocketAddr {
    SocketAddr::new("127.0.0.1".parse::<IpAddr>().unwrap(), 54321)
}

fn make_metadata() -> Metadata {
    Metadata {
        host: "example.com".to_string(),
        dst_port: 53,
        src_ip: Some("127.0.0.1".parse().unwrap()),
        src_port: 54321,
        ..Default::default()
    }
}

/// Current implementation: format! allocates a String key on every packet.
#[inline(never)]
fn nat_key_current(src: SocketAddr, metadata: &Metadata) -> String {
    format!("{}:{}", src, metadata.remote_address())
}

fn bench_udp_nat_key(c: &mut Criterion) {
    let src = make_src();
    let metadata = make_metadata();

    let mut group = c.benchmark_group("udp_nat_key");

    // Measure: key construction only (the String allocation)
    group.bench_function("key_alloc", |b| {
        b.iter(|| black_box(nat_key_current(black_box(src), black_box(&metadata))));
    });

    // Measure: key construction + DashMap lookup (hit path — most common case)
    {
        let table: Arc<DashMap<String, u64>> = Arc::new(DashMap::new());
        let precomputed_key = nat_key_current(src, &metadata);
        table.insert(precomputed_key, 42u64);

        group.bench_function("lookup_hit", |b| {
            b.iter(|| {
                let key = nat_key_current(black_box(src), black_box(&metadata));
                black_box(table.get(&key).map(|v| *v))
            });
        });
    }

    // Measure: key construction + DashMap lookup (miss path — new session)
    {
        let table: Arc<DashMap<String, u64>> = Arc::new(DashMap::new());

        group.bench_function("lookup_miss", |b| {
            b.iter(|| {
                let key = nat_key_current(black_box(src), black_box(&metadata));
                black_box(table.get(&key))
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_udp_nat_key);
criterion_main!(benches);
