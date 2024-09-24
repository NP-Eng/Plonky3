use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use rand::thread_rng;

#[path = "../common.rs"]
mod common;
use common::N_PAIRS;

type GF = Goldilocks;
type Perm = Poseidon2<GF, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7>;

fn poseidon_hasher() -> PaddingFreeSponge<Perm, 16, 8, 8> {
    let perm = Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks::default(),
        &mut thread_rng(),
    );

    PaddingFreeSponge::new(perm)
}

fn main() {
    let hasher = poseidon_hasher();

    let pairs: Vec<Vec<GF>> = vec![vec![rand::random::<GF>(), rand::random::<GF>()]; N_PAIRS];

    let start = std::time::Instant::now();

    pairs.into_iter().for_each(|pair| {
        hasher.hash_iter(pair);
    });

    let elapsed = start.elapsed();

    println!("Two-to-one Poseidon hash");
    println!("Goldilocks field");
    println!("{N_PAIRS} pairs");
    println!("Time: {:?}", elapsed);
    println!("Time per iteration: {:?}", elapsed / N_PAIRS as u32);
}
