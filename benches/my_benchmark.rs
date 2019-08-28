#[macro_use]
extern crate criterion;

extern crate aes_s;

use aes_s::cipher::Cipher;
use criterion::black_box;
use criterion::Criterion;
use std::fs::File;
use std::io;
use std::io::prelude::*;

fn criterion_benchmark(c: &mut Criterion) {
    //// 128 ////

    let mut content: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let password: [u32; 4] = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
    let cipher = Cipher::new_128(&password);

    c.bench_function("cipher 128", |b| {
        b.iter(|| {
            black_box({
                cipher.cipher(&mut content);
                cipher.decipher(&mut content);
            })
        })
    });

    //// -128- ////

    //// 192 ////
    let mut content: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let password: [u32; 6] = [
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617,
    ];
    let cipher = Cipher::new_192(&password);

    c.bench_function("cipher 192", |b| {
        b.iter(|| {
            black_box({
                cipher.cipher(&mut content);
                cipher.decipher(&mut content);
            })
        })
    });

    //// - 192- ////

    //// 256 ////

    let mut content: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let password: [u32; 8] = [
        0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
        0x1c1d1e1f,
    ];
    let cipher = Cipher::new_256(&password);
    c.bench_function("cipher 256", |b| {
        b.iter(|| {
            black_box({
                cipher.cipher(&mut content);
                cipher.decipher(&mut content);
            })
        })
    });

    //// -256- ////
    /*c.bench_function("read from file", |b| {
        b.iter(|| {
            black_box({
                let key_128 = [0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF];
                let cipher = Cipher::new_128(&key_128);

                let mut f = File::open("benches/foo.txt").unwrap();
                let mut buffer = [0; 16];
                let mut result = Vec::new();

                let mut count = f.read(&mut buffer).unwrap();
                while count != 0 {
                    cipher.cipher(&mut buffer);
                    result.extend_from_slice(&buffer);
                    buffer = [0; 16];
                    count = f.read(&mut buffer).unwrap();
                }

                let mut buffer = File::create("benches/foo.cpt").unwrap();
                buffer.write_all(&result).unwrap();
            })
        })
    });

    c.bench_function("read from file dec", |b| {
        b.iter(|| {
            black_box({
                let key_128 = [0x00112233, 0x44556677, 0x8899AABB, 0xCCDDEEFF];
                let cipher = Cipher::new_128(&key_128);

                let mut f = File::open("benches/foo.cpt").unwrap();
                let mut buffer = [0; 16];
                let mut result = Vec::new();

                let mut count = f.read(&mut buffer).unwrap();
                while count != 0 {
                    cipher.decipher(&mut buffer);
                    result.extend_from_slice(&buffer);
                    buffer = [0; 16];
                    count = f.read(&mut buffer).unwrap();
                }

                let mut buffer = File::create("benches/foo.txt").unwrap();
                buffer.write_all(&result).unwrap();
            })
        })
    });*/
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
