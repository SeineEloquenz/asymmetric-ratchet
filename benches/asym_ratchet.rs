use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};

static PAYLOAD: &[u8] = include_bytes!("payload.txt");

fn bench_asym_ratchet(c: &mut Criterion) {
    let mut group = c.benchmark_group("asym_ratchet");
    group.throughput(Throughput::Elements(1));
    group.bench_function("generate_keypair", |b| {
        b.iter(|| asym_ratchet::generate_keypair(rand::thread_rng()))
    });

    let (mut pub_key, mut priv_key) = asym_ratchet::generate_keypair(rand::thread_rng());

    group.bench_function("PublicKey::ratchet", |b| b.iter(|| pub_key.ratchet()));

    group.bench_function("PrivateKey::ratchet", |b| {
        b.iter(|| priv_key.ratchet(rand::thread_rng()))
    });
    group.finish();

    let (pub_key, priv_key) = asym_ratchet::generate_keypair(rand::thread_rng());

    let mut group = c.benchmark_group("asym_ratchet/encrypt");
    for size in (512usize..=10240).step_by(512) {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || (&PAYLOAD[..size]).to_vec(),
                |input| pub_key.encrypt(rand::thread_rng(), input).unwrap(),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();

    let mut group = c.benchmark_group("asym_ratchet/decrypt");
    for size in (512usize..=10240).step_by(512) {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched(
                || {
                    pub_key
                        .encrypt(rand::thread_rng(), (&PAYLOAD[..size]).to_vec())
                        .unwrap()
                },
                |input| priv_key.decrypt(input),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();

    #[cfg(feature = "serde")]
    {
        let (pub_key, priv_key) =
            asym_ratchet::keyprivate::wrap_keypair(rand::thread_rng(), (pub_key, priv_key));

        let mut group = c.benchmark_group("asym_ratchet/keyprivate/encrypt");
        for size in (512usize..=10240).step_by(512) {
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
                b.iter_batched(
                    || (&PAYLOAD[..size]).to_vec(),
                    |input| pub_key.encrypt(rand::thread_rng(), input).unwrap(),
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();

        let mut group = c.benchmark_group("asym_ratchet/keyprivate/decrypt");
        for size in (512usize..=10240).step_by(512) {
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
                b.iter_batched(
                    || {
                        pub_key
                            .encrypt(rand::thread_rng(), (&PAYLOAD[..size]).to_vec())
                            .unwrap()
                    },
                    |input| priv_key.decrypt(input),
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_asym_ratchet);
criterion_main!(benches);
