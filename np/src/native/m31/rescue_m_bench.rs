use p3_mersenne_31::{MdsMatrixMersenne31, Mersenne31};
use p3_rescue::{BasicSboxLayer, Rescue};
use p3_symmetric::{
    CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation,
};
use rand::thread_rng;

#[path = "../../common.rs"]
mod common;
use common::N_ITERS;

type M31 = Mersenne31;
type Mds = MdsMatrixMersenne31;
type RescuePerm = Rescue<M31, Mds, BasicSboxLayer<M31>, 16>;
type RescueH = PaddingFreeSponge<RescuePerm, 16, 8, 8>;
type RescueC = TruncatedPermutation<RescuePerm, 2, 8, 16>;

fn rescue_hashers() -> (RescueH, RescueC) {
    let mds = Mds::default();

    let round_constants = RescuePerm::get_round_constants_from_rng(8, &mut thread_rng());
    let perm = RescuePerm::new(8, round_constants, mds, BasicSboxLayer::for_alpha(5));

    (RescueH::new(perm.clone()), RescueC::new(perm))
}

fn main() {
    let (h, c) = rescue_hashers();

    let field_els: Vec<Vec<M31>> = vec![vec![rand::random::<M31>()]; N_ITERS];

    let start = std::time::Instant::now();

    field_els.into_iter().for_each(|e| {
        h.hash_iter(e);
    });

    let elapsed = start.elapsed();

    println!("Rescue Mersenne31 (32 bits) bits to 256 bits");
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

    println!("Rescue Mersenne31 512 bits to 256 bits");
    println!("\t{N_ITERS} inputs");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_ITERS as u32);
}
