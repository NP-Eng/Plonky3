use p3_keccak::Keccak256Hash;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, PseudoCompressionFunction,
    SerializingHasher32,
};

#[path = "../../common.rs"]
mod common;
use common::N_ITERS;

type M31 = Mersenne31;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher32<ByteHash>;
type KeccakC = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;

fn main() {
    let byte_hash = ByteHash {};
    let hasher = FieldHash::new(byte_hash);
    let compressor = KeccakC::new(Keccak256Hash {});

    let field_els: Vec<Vec<M31>> = vec![vec![rand::random::<M31>()]; N_ITERS];

    let start = std::time::Instant::now();

    field_els.into_iter().for_each(|e| {
        hasher.hash_iter(e);
    });

    let elapsed = start.elapsed();

    println!("Keccak Mersenne31 (32 bits) bits to 256 bits");
    println!("\t{N_ITERS} inputs");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per element: {:?}", elapsed / N_ITERS as u32);

    let field_pairs: Vec<(M31, M31)> =
        vec![(rand::random::<M31>(), rand::random::<M31>()); N_ITERS];

    let digest_pairs: Vec<[[u8; 32]; 2]> = field_pairs
        .into_iter()
        .map(|pair| [hasher.hash_iter([pair.0]), hasher.hash_iter([pair.1])])
        .collect();

    let start = std::time::Instant::now();

    digest_pairs.into_iter().for_each(|pair| {
        compressor.compress(pair);
    });

    let elapsed = start.elapsed();

    println!("Keccak 512 bits to 256 bits");
    println!("\t{N_ITERS} inputs");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_ITERS as u32);
}
