use std::collections::HashMap;

use criterion::{BatchSize, BenchmarkId, Criterion};
use p3_baby_bear::BabyBear;
use p3_field::Field;
use p3_matrix::Matrix;
use p3_merkle_tree::{
    HybridMerkleTree, MerkleTree, SimpleHybridCompressor, UnsafeNodeConverter256BabyBearBytes,
};
use p3_symmetric::IdentityHasher;

mod common;
use common::*;

type BabyBearPacking = <BabyBear as Field>::Packing;
type HIdentityBabyBear256 = IdentityHasher<8>;

const MAX_ROWS: usize = 1 << 15;
const MAX_COLS: usize = 2;
const NUM_MATRICES: usize = 200;

fn main() {
    let mut criterion = Criterion::default();

    let h_identity = HIdentityBabyBear256 {};
    let c_poseidon = poseidon2_compressor();
    let c_blake3 = blake3_compressor();

    let c_hybrid =
        SimpleHybridCompressor::<_, _, _, _, 8, 32, UnsafeNodeConverter256BabyBearBytes>::new(
            c_poseidon.clone(),
            c_blake3.clone(),
            false,
        );

    let leaves = get_random_leaves(NUM_MATRICES, MAX_ROWS, MAX_COLS);

    let mut pow_2_seen = HashMap::new();

    // Filter out extra matrices with heights that occur more than 8 times,
    // this done in order to prevent the IdentityHasher from panicking.
    let filtered_leaves = leaves
        .into_iter()
        .filter(|l| {
            let n_rows = l.height();
            let n_rows = pow_2_seen
                .entry(n_rows)
                .and_modify(|v| *v += 1)
                .or_insert(1);
            *n_rows <= 8
        })
        .collect::<Vec<_>>();

    let mut group = criterion.benchmark_group("MerkleTree vs HybridMerkleTree with IdentityHasher");
    group.sample_size(10);

    bench_plain_merkle_tree!(
        &mut group,
        "Poseidon2 compressor, WIDTH = 1",
        &h_identity,
        &c_poseidon,
        filtered_leaves,
        1
    );

    bench_plain_merkle_tree!(
        &mut group,
        "Poseidon2 compressor, WIDTH = 4",
        &h_identity,
        &c_poseidon,
        filtered_leaves,
        4
    );

    bench_hybrid_merkle_tree!(
        &mut group,
        "Hybrid Blake3/Poseidon2 compressor, WIDTH = 1",
        &h_identity,
        &c_hybrid,
        filtered_leaves
    );
}
