use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation};
use rand::thread_rng;

#[path = "../common.rs"]
mod common;
use common::N_ITERS;

type GF = Goldilocks;
type PoseidonPerm = Poseidon2<GF, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7>;
type PoseidonH = PaddingFreeSponge<PoseidonPerm, 16, 8, 8>;
type PoseidonC = TruncatedPermutation<PoseidonPerm, 2, 8, 16>;

fn poseidon_hashers() -> (PoseidonH, PoseidonC) {
    let perm = PoseidonPerm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks::default(),
        &mut thread_rng(),
    );

    (PoseidonH::new(perm.clone()), PoseidonC::new(perm))
}

fn main() {
    let (h, c) = poseidon_hashers();

    let field_els: Vec<Vec<GF>> = vec![vec![rand::random::<GF>()]; N_ITERS];

    let start = std::time::Instant::now();

    field_els.into_iter().for_each(|e| {
        h.hash_iter(e);
    });

    let elapsed = start.elapsed();

    println!("Poseidon Goldilocks (64 bits) bits to 256 bits");
    println!("\t{N_ITERS} elements");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_ITERS as u32);

    let field_pairs: Vec<(GF, GF)> = vec![(rand::random::<GF>(), rand::random::<GF>()); N_ITERS];
    
    let digest_pairs: Vec<[[Goldilocks; 8]; 2]> = field_pairs
        .into_iter()
        .map(|pair| [h.hash_iter([pair.0]), h.hash_iter([pair.1])])
        .collect();

    let start = std::time::Instant::now();

    digest_pairs.into_iter().for_each(|pair| {
        c.compress(pair);
    });

    let elapsed = start.elapsed();

    println!("Poseidon 512 bits to 256 bits");
    println!("\t{N_ITERS} inputs");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_ITERS as u32);
}
