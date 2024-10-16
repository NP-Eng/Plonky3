use p3_mersenne_31::{DiffusionMatrixMersenne31, Mersenne31};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{
    CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
};
use rand::thread_rng;

#[path = "../common.rs"]
mod common;
use common::N_ITERS;

type M31 = Mersenne31;
type PoseidonPerm =
    Poseidon2<Mersenne31, Poseidon2ExternalMatrixGeneral, DiffusionMatrixMersenne31, 16, 5>;
type PoseidonH = PaddingFreeSponge<PoseidonPerm, 16, 8, 8>;

fn main() {
    let h = PoseidonH::new(PoseidonPerm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixMersenne31::default(),
        &mut thread_rng(),
    ));

    println!("Poseidon Mersenne31 digest: n field elements (32 bits each) bits to 8 field elements (256 bits in total)");
    println!("Permutation width = 16, rate = 8 (capacity = 8), output = 8");
    println!("Average over {N_ITERS} iterations");

    println!("Warming up...");
    for _ in 0..N_ITERS {
        h.hash_iter(vec![rand::random::<M31>()]);
    }

    for n in 1..34 {
        let field_els: Vec<Vec<M31>> = vec![vec![rand::random::<M31>(); n]; N_ITERS];

        let start = std::time::Instant::now();

        field_els.into_iter().for_each(|e| {
            h.hash_iter(e);
        });

        let elapsed = start.elapsed();

        println!(
            "- n = {n}, time per iteration: {:?}",
            elapsed / N_ITERS as u32
        );
    }
}
