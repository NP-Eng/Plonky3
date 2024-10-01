use p3_blake3::Blake3;
use p3_goldilocks::Goldilocks;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, PseudoCompressionFunction,
    SerializingHasher64,
};

#[path = "../../common.rs"]
mod common;
use common::N_ITERS;

type GF = Goldilocks;
type ByteHash = Blake3;
type FieldHash = SerializingHasher64<Blake3>;
type Blake3C = CompressionFunctionFromHasher<Blake3, 2, 32>;

fn main() {
    let byte_hash = ByteHash {};
    let hasher = FieldHash::new(byte_hash);
    let compressor = Blake3C::new(Blake3 {});

    let field_els: Vec<Vec<GF>> = vec![vec![rand::random::<GF>()]; N_ITERS];

    let start = std::time::Instant::now();

    field_els.into_iter().for_each(|e| {
        hasher.hash_iter(e);
    });

    let elapsed = start.elapsed();

    println!("Blake3 Goldilocks (64 bits) bits to 256 bits");
    println!("\t{N_ITERS} inputs");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per element: {:?}", elapsed / N_ITERS as u32);

    let field_pairs: Vec<(GF, GF)> = vec![(rand::random::<GF>(), rand::random::<GF>()); N_ITERS];

    let digest_pairs: Vec<[[u8; 32]; 2]> = field_pairs
        .into_iter()
        .map(|pair| [hasher.hash_iter([pair.0]), hasher.hash_iter([pair.1])])
        .collect();

    let start = std::time::Instant::now();

    digest_pairs.into_iter().for_each(|pair| {
        //
        compressor.compress(pair);
        // byte_hash.hash_iter(pair.concat());
    });

    let elapsed = start.elapsed();

    println!("Blake3 Goldilocks 512 bits to 256 bits");
    println!("\t{N_ITERS} inputs");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_ITERS as u32);
}
