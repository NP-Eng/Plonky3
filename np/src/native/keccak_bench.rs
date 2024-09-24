use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher64};

#[path = "../common.rs"]
mod common;
use common::N_ITERS;

type GF = Goldilocks;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher64<ByteHash>;

fn main() {
    let byte_hash = ByteHash {};
    let hasher = FieldHash::new(byte_hash);

    let field_els: Vec<Vec<GF>> = vec![vec![rand::random::<GF>()]; N_ITERS];

    let start = std::time::Instant::now();

    field_els.into_iter().for_each(|e| {
        hasher.hash_iter(e);
    });

    let elapsed = start.elapsed();

    println!("Keccak Goldilocks (64 bits) bits to 256 bits");
    println!("{N_ITERS} inputs");
    println!("Time: {:?}", elapsed);
    println!("Time per element: {:?}", elapsed / N_ITERS as u32);

    let field_pairs: Vec<(GF, GF)> = vec![(rand::random::<GF>(), rand::random::<GF>()); N_ITERS];

    let digest_pairs: Vec<Vec<[u8; 32]>> = field_pairs
        .into_iter()
        .map(|pair| vec![hasher.hash_iter([pair.0]), hasher.hash_iter([pair.1])])
        .collect();

    let start = std::time::Instant::now();

    digest_pairs.into_iter().for_each(|pair| {
        byte_hash.hash_iter(pair.concat());
    });

    let elapsed = start.elapsed();

    println!("Keccak 512 bits to 256 bits");
    println!("{N_ITERS} inputs");
    println!("Time: {:?}", elapsed);
    println!("Time per iteration: {:?}", elapsed / N_ITERS as u32);
}
