#[allow(unused)]
use std::any::type_name;
use std::time::Instant;

use p3_blake3::Blake3;
use p3_field::{Field, PackedField, PackedValue};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_mds::integrated_coset_mds::IntegratedCosetMds;
use p3_merkle_tree::MerkleTree;
use p3_mersenne_31::{DiffusionMatrixMersenne31, MdsMatrixMersenne31, Mersenne31};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_rescue::{BasicSboxLayer, Rescue};
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, PaddingFreeSponge,
    PseudoCompressionFunction, SerializingHasher32, SerializingHasher64, TruncatedPermutation,
};
use rand::distributions::{Distribution, Standard};
use rand::{thread_rng, Rng};
use serde::de::DeserializeOwned;
use serde::Serialize;

mod common;

use common::*;

type M31 = Mersenne31;

// ************* Poseidon2 Types *************
type PoseidonPerm =
    Poseidon2<Mersenne31, Poseidon2ExternalMatrixGeneral, DiffusionMatrixMersenne31, 16, 5>;
type PoseidonH = PaddingFreeSponge<PoseidonPerm, 16, 8, 8>;
type PoseidonC = TruncatedPermutation<PoseidonPerm, 2, 8, 16>;

// *************** Keccak Types **************
type Keccak = Keccak256Hash;
type KeccakH = SerializingHasher32<Keccak>;
type KeccakC = CompressionFunctionFromHasher<Keccak256Hash, 2, 32>;

// *************** Blake3 Types ***************
type Blake3H = SerializingHasher32<Blake3>;
type Blake3C = CompressionFunctionFromHasher<Blake3, 2, 32>;

// ************** Rescue Types ***************
type Mds = MdsMatrixMersenne31;
type RescuePerm = Rescue<M31, Mds, BasicSboxLayer<M31>, 16>;
type RescueH = PaddingFreeSponge<RescuePerm, 16, 8, 8>;
type RescueC = TruncatedPermutation<RescuePerm, 2, 8, 16>;

fn bench_poseidon2() {
    let perm = PoseidonPerm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixMersenne31::default(),
        &mut thread_rng(),
    );

    let h = PoseidonH::new(perm.clone());
    let c = PoseidonC::new(perm);

    bench_merkle_tree::<M31, M31, PoseidonH, PoseidonC, 8>(h, c);
}

fn bench_keccak() {
    let h = KeccakH::new(Keccak {});
    let c = KeccakC::new(Keccak {});

    bench_merkle_tree::<M31, u8, KeccakH, KeccakC, 32>(h, c);
}

fn bench_blake3() {
    let h = Blake3H::new(Blake3 {});
    let c = Blake3C::new(Blake3 {});

    bench_merkle_tree::<M31, u8, Blake3H, Blake3C, 32>(h, c);
}

fn bench_rescue() {
    let mds = Mds::default();

    let round_constants = RescuePerm::get_round_constants_from_rng(8, &mut thread_rng());
    let perm = RescuePerm::new(8, round_constants, mds, BasicSboxLayer::for_alpha(5));

    let h = RescueH::new(perm.clone());
    let c = RescueC::new(perm);

    bench_merkle_tree::<M31, M31, RescueH, RescueC, 8>(h, c);
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
    // init_logger();

    println!("\n * Poseidon2");
    estimate_commitment_time(LEVEL_N, "Poseidon2", "Poseidon2", "Mersenne31");
    bench_poseidon2();

    println!("\n * Keccak");
    estimate_commitment_time(LEVEL_N, "Keccak", "Keccak", "Mersenne31");
    bench_keccak();

    println!("\n * Blake3");
    estimate_commitment_time(LEVEL_N, "Blake3", "Blake3", "Mersenne31");
    bench_blake3();

    println!("\n * Rescue");
    estimate_commitment_time(LEVEL_N, "Rescue", "Rescue", "Mersenne31");
    bench_rescue();

    println!("");

    estimate_commitment_time(LEVEL_N, "Poseidon2", "Poseidon2", "Mersenne31");
    estimate_commitment_time(LEVEL_N, "Blake3", "Poseidon2", "Mersenne31");
}

pub fn init_logger() {
    let _ = env_logger::builder().format_timestamp(None).try_init();
}
