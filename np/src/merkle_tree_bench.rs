#[allow(unused)]
use std::any::type_name;
use std::time::Instant;

use common::*;
use p3_blake3::Blake3;
use p3_field::{Field, PackedField, PackedValue};
use p3_goldilocks::{DiffusionMatrixGoldilocks, Goldilocks};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_mds::integrated_coset_mds::IntegratedCosetMds;
use p3_merkle_tree::MerkleTree;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_rescue::{BasicSboxLayer, Rescue};
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, PaddingFreeSponge,
    PseudoCompressionFunction, SerializingHasher64, TruncatedPermutation,
};
use rand::distributions::{Distribution, Standard};
use rand::thread_rng;
use serde::de::DeserializeOwned;
use serde::Serialize;

// log2 of the number of leaves
const LEVEL_N: usize = 13;
// log2 of the number of caps
const LEVEL_K: usize = 0;

mod common;

type GF = Goldilocks;
type P = <GF as Field>::Packing;

// ************* Poseidon2 Types *************
type PoseidonPerm = Poseidon2<GF, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7>;
type PoseidonH = PaddingFreeSponge<PoseidonPerm, 16, 8, 8>;
type PoseidonC = TruncatedPermutation<PoseidonPerm, 2, 8, 16>;

// *************** Keccak Types **************
type Keccak = Keccak256Hash;
type KeccakH = SerializingHasher64<Keccak>;
type KeccakC = CompressionFunctionFromHasher<u8, Keccak, 2, 32>;

// *************** Blake3 Types ***************
type Blake3H = SerializingHasher64<Blake3>;
type Blake3C = CompressionFunctionFromHasher<u8, Blake3, 2, 32>;

// ************** Rescue Types ***************
type Mds = IntegratedCosetMds<GF, 16>;
type RescuePerm = Rescue<GF, Mds, BasicSboxLayer<GF>, 16>;
type RescueH = PaddingFreeSponge<RescuePerm, 16, 8, 8>;
type RescueC = TruncatedPermutation<RescuePerm, 2, 8, 16>;

fn bench_bb_poseidon2() {
    let perm = PoseidonPerm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks::default(),
        &mut thread_rng(),
    );

    let h = PoseidonH::new(perm.clone());
    let c = PoseidonC::new(perm);

    bench_merkle_tree::<P, P, PoseidonH, PoseidonC, 8>(h, c);
}

fn bench_bb_rescue() {
    let mds = Mds::default();

    let round_constants = RescuePerm::get_round_constants_from_rng(8, &mut thread_rng());
    let perm = RescuePerm::new(8, round_constants, mds, BasicSboxLayer::for_alpha(7));

    let h = RescueH::new(perm.clone());
    let c = RescueC::new(perm);

    bench_merkle_tree::<P, P, RescueH, RescueC, 8>(h, c);
}

fn bench_bb_blake3() {
    let h = Blake3H::new(Blake3 {});
    let c = Blake3C::new(Blake3 {});

    bench_merkle_tree::<GF, u8, Blake3H, Blake3C, 32>(h, c);
}

fn bench_bb_keccak() {
    let h = KeccakH::new(Keccak {});
    let c = KeccakC::new(Keccak {});

    bench_merkle_tree::<GF, u8, KeccakH, KeccakC, 32>(h, c);
}

fn bench_merkle_tree<P, PW, H, C, const DIGEST_ELEMS: usize>(h: H, c: C)
where
    P: PackedField,
    PW: PackedValue,
    H: CryptographicHasher<P::Scalar, [PW::Value; DIGEST_ELEMS]>,
    H: CryptographicHasher<P, [PW; DIGEST_ELEMS]>,
    H: Sync,
    C: PseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], 2>,
    C: PseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>,
    C: Sync,
    [PW::Value; DIGEST_ELEMS]: Serialize + DeserializeOwned,
    Standard: Distribution<P::Scalar>,
{
    let leaves = vec![RowMajorMatrix::<P::Scalar>::rand(
        &mut thread_rng(),
        1 << LEVEL_N,
        1,
    )];

    let start = Instant::now();
    let tree = MerkleTree::new::<P, PW, H, C>(&h, &c, leaves);
    let elapsed = start.elapsed();

    // TODO remove
    // for (i, level) in tree.digest_layers.into_iter().enumerate() {
    //     println!("Level: {i}, length: {}", level.len());
    // }

    println!("Merkle tree built in {:?}", elapsed);
}

fn main() {
    init_logger();

    println!("\n * Poseidon2");
    estimate_commitment_time(LEVEL_N, "Poseidon2", "Poseidon2");
    bench_bb_poseidon2();

    println!("\n * Keccak");
    estimate_commitment_time(LEVEL_N, "Keccak", "Keccak");
    bench_bb_keccak();

    println!("\n * Blake3");
    estimate_commitment_time(LEVEL_N, "Blake3", "Blake3");
    bench_bb_blake3();

    println!("\n * Rescue");
    estimate_commitment_time(LEVEL_N, "Rescue", "Rescue");
    bench_bb_rescue();
}

pub fn init_logger() {
    let _ = env_logger::builder().format_timestamp(None).try_init();
}
