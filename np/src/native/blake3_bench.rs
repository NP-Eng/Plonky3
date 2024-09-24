use p3_blake3::Blake3;
use p3_goldilocks::Goldilocks;
use p3_symmetric::{CryptographicHasher, SerializingHasher64};

#[path = "../common.rs"]
mod common;
use common::N_PAIRS;

type GF = Goldilocks;
type ByteHash = Blake3;
type FieldHash = SerializingHasher64<Blake3>;

fn main() {
    let byte_hash = ByteHash {};
    let hasher = FieldHash::new(byte_hash);

    let pairs: Vec<Vec<GF>> = vec![vec![rand::random::<GF>(), rand::random::<GF>()]; N_PAIRS];
    let start = std::time::Instant::now();

    pairs.into_iter().for_each(|pair| {
        // TODO fix
        println!(
            "Blake3 for {} elements of size {}",
            pair.len(),
            std::mem::size_of::<GF>()
        );
        let start = std::time::Instant::now();
        hasher.hash_iter(pair);
        let elapsed = start.elapsed();
        println!("   time: {:?}", elapsed);
    });

    let elapsed = start.elapsed();

    println!("Two-to-one Blake3 hash");
    println!("Goldilocks field");
    println!("{N_PAIRS} pairs");
    println!("Time: {:?}", elapsed);
    println!("Time per iteration: {:?}", elapsed / N_PAIRS as u32);
}
