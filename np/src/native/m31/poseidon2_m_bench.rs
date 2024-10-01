use p3_mersenne_31::{DiffusionMatrixMersenne31, Mersenne31};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{
    CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
};
use rand::thread_rng;

#[path = "../../common.rs"]
mod common;
use common::N_ITERS;

type M31 = Mersenne31;
type PoseidonPerm =
    Poseidon2<Mersenne31, Poseidon2ExternalMatrixGeneral, DiffusionMatrixMersenne31, 16, 5>;
type PoseidonH = PaddingFreeSponge<PoseidonPerm, 16, 8, 8>;
type PoseidonC = TruncatedPermutation<PoseidonPerm, 2, 8, 16>;

fn poseidon_hashers() -> (PoseidonH, PoseidonC) {
    let perm = PoseidonPerm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixMersenne31::default(),
        &mut thread_rng(),
    );

    (PoseidonH::new(perm.clone()), PoseidonC::new(perm))
}

fn main() {
    let (h, c) = poseidon_hashers();

    let field_els: Vec<Vec<M31>> = vec![vec![rand::random::<M31>()]; N_ITERS];

    let start = std::time::Instant::now();

    field_els.into_iter().for_each(|e| {
        h.hash_iter(e);
    });

    let elapsed = start.elapsed();

    println!("Poseidon Mersenne31 (32 bits) bits to 256 bits");
    println!("\t{N_ITERS} elements");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_ITERS as u32);

    let field_pairs: Vec<(M31, M31)> =
        vec![(rand::random::<M31>(), rand::random::<M31>()); N_ITERS];

    let digest_pairs: Vec<[[M31; 8]; 2]> = field_pairs
        .into_iter()
        .map(|pair| [h.hash_iter([pair.0]), h.hash_iter([pair.1])])
        .collect();

    let start = std::time::Instant::now();

    digest_pairs.into_iter().for_each(|pair| {
        c.compress(pair);
    });

    let elapsed = start.elapsed();

    println!("Poseidon Mersenne31 512 bits to 256 bits");
    println!("\t{N_ITERS} inputs");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_ITERS as u32);
}
