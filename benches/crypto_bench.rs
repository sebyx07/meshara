//! Cryptographic benchmarks for Meshara

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use meshara::crypto::{
    decrypt_message, encrypt_for_recipient, hash_message, hash_public_key, sign_message,
    verify_signature, Identity,
};
use std::hint::black_box;

fn benchmark_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation", |b| {
        b.iter(|| {
            let identity = Identity::generate();
            black_box(identity)
        })
    });
}

fn benchmark_signing(c: &mut Criterion) {
    let identity = Identity::generate();
    let message = b"Test message for signing benchmark";

    c.bench_function("sign_message", |b| {
        b.iter(|| {
            let signature = sign_message(&identity, black_box(message));
            black_box(signature)
        })
    });
}

fn benchmark_verification(c: &mut Criterion) {
    let identity = Identity::generate();
    let public_key = identity.public_key();
    let message = b"Test message for verification benchmark";
    let signature = sign_message(&identity, message);

    c.bench_function("verify_signature", |b| {
        b.iter(|| {
            let result = verify_signature(&public_key, black_box(message), &signature);
            black_box(result)
        })
    });
}

fn benchmark_encryption(c: &mut Criterion) {
    let sender = Identity::generate();
    let recipient = Identity::generate();
    let recipient_pubkey = recipient.public_key();

    let mut group = c.benchmark_group("encryption");

    for size in [64, 1024, 4096, 65536].iter() {
        let message = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let encrypted =
                    encrypt_for_recipient(&sender, &recipient_pubkey, black_box(&message)).unwrap();
                black_box(encrypted)
            })
        });
    }

    group.finish();
}

fn benchmark_decryption(c: &mut Criterion) {
    let sender = Identity::generate();
    let recipient = Identity::generate();
    let recipient_pubkey = recipient.public_key();

    let mut group = c.benchmark_group("decryption");

    for size in [64, 1024, 4096, 65536].iter() {
        let message = vec![0u8; *size];
        let encrypted = encrypt_for_recipient(&sender, &recipient_pubkey, &message).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let decrypted = decrypt_message(&recipient, black_box(&encrypted)).unwrap();
                black_box(decrypted)
            })
        });
    }

    group.finish();
}

fn benchmark_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    for size in [64, 1024, 4096, 65536].iter() {
        let data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                let hash = hash_message(black_box(&data));
                black_box(hash)
            })
        });
    }

    group.finish();
}

fn benchmark_hash_public_key(c: &mut Criterion) {
    let identity = Identity::generate();
    let public_key = identity.public_key();

    c.bench_function("hash_public_key", |b| {
        b.iter(|| {
            let hash = hash_public_key(black_box(&public_key));
            black_box(hash)
        })
    });
}

fn benchmark_key_export(c: &mut Criterion) {
    let identity = Identity::generate();
    let passphrase = "benchmark passphrase";

    c.bench_function("key_export", |b| {
        b.iter(|| {
            let exported = identity.export_encrypted(black_box(passphrase)).unwrap();
            black_box(exported)
        })
    });
}

fn benchmark_key_import(c: &mut Criterion) {
    let identity = Identity::generate();
    let passphrase = "benchmark passphrase";
    let exported = identity.export_encrypted(passphrase).unwrap();

    c.bench_function("key_import", |b| {
        b.iter(|| {
            let imported =
                Identity::import_encrypted(black_box(&exported), black_box(passphrase)).unwrap();
            black_box(imported)
        })
    });
}

criterion_group!(
    benches,
    benchmark_key_generation,
    benchmark_signing,
    benchmark_verification,
    benchmark_encryption,
    benchmark_decryption,
    benchmark_hashing,
    benchmark_hash_public_key,
    benchmark_key_export,
    benchmark_key_import
);
criterion_main!(benches);
