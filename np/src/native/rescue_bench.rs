use p3_goldilocks::Goldilocks;
use p3_mds::integrated_coset_mds::IntegratedCosetMds;
use p3_rescue::{BasicSboxLayer, Rescue};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use rand::thread_rng;

#[path = "../common.rs"]
mod common;
use common::N_PAIRS;

type GF = Goldilocks;
type Perm = Rescue<GF, Mds, BasicSboxLayer<GF>, 16>;
type Mds = IntegratedCosetMds<GF, 16>;

fn rescue_hasher() -> PaddingFreeSponge<Perm, 16, 8, 8> {
    let mds = Mds::default();

    let round_constants = Perm::get_round_constants_from_rng(8, &mut thread_rng());
    let perm = Perm::new(8, round_constants, mds, BasicSboxLayer::for_alpha(7));

    PaddingFreeSponge::new(perm)
}

fn main() {
    let hasher = rescue_hasher();

    let pairs: Vec<Vec<GF>> = vec![vec![rand::random::<GF>(), rand::random::<GF>()]; N_PAIRS];

    let start = std::time::Instant::now();

    pairs.into_iter().for_each(|pair| {
        hasher.hash_iter(pair);
    });

    let elapsed = start.elapsed();

    println!("Two-to-one Rescue hash");
    println!("Goldilocks field");
    println!("{N_PAIRS} elements");
    println!("Time: {:?}", elapsed);
    println!("Time per iteration: {:?}", elapsed / N_PAIRS as u32);
}
