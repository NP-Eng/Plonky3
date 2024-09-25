use p3_goldilocks::Goldilocks;
use p3_mds::integrated_coset_mds::IntegratedCosetMds;
use p3_rescue::{BasicSboxLayer, Rescue};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, PseudoCompressionFunction, TruncatedPermutation};
use rand::thread_rng;

#[path = "../common.rs"]
mod common;
use common::N_ITERS;

type GF = Goldilocks;
type Mds = IntegratedCosetMds<GF, 16>;
type RescuePerm = Rescue<GF, Mds, BasicSboxLayer<GF>, 16>;
type RescueH = PaddingFreeSponge<RescuePerm, 16, 8, 8>;
type RescueC = TruncatedPermutation<RescuePerm, 2, 8, 16>;

fn rescue_hashers() -> (RescueH, RescueC) {
    let mds = Mds::default();

    let round_constants = RescuePerm::get_round_constants_from_rng(8, &mut thread_rng());
    let perm = RescuePerm::new(8, round_constants, mds, BasicSboxLayer::for_alpha(7));

    
    (RescueH::new(perm.clone()), RescueC::new(perm))
}

fn main() {
    let (h, c) = rescue_hashers();

    let field_els: Vec<Vec<GF>> = vec![vec![rand::random::<GF>()]; N_ITERS];

    let start = std::time::Instant::now();

    field_els.into_iter().for_each(|e| {
        h.hash_iter(e);
    });

    let elapsed = start.elapsed();

    println!("Rescue Goldilocks (64 bits) bits to 256 bits");
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

    println!("Rescue 512 bits to 256 bits");
    println!("\t{N_ITERS} inputs");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_ITERS as u32);
}
