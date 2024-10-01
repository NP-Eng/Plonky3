#[allow(unused)]
use std::any::type_name;
use std::time::Instant;

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

mod common;

use common::*;

type GF = Goldilocks;

// ************* Poseidon2 Types *************
type PoseidonPerm = Poseidon2<GF, Poseidon2ExternalMatrixGeneral, DiffusionMatrixGoldilocks, 16, 7>;
type PoseidonH = PaddingFreeSponge<PoseidonPerm, 16, 8, 4>;
type PoseidonC = TruncatedPermutation<PoseidonPerm, 2, 4, 16>;

// *************** Keccak Types **************
type Keccak = Keccak256Hash;
type KeccakH = SerializingHasher64<Keccak>;
type KeccakC = CompressionFunctionFromHasher<Keccak, 2, 32>;

// *************** Blake3 Types ***************
type Blake3H = SerializingHasher64<Blake3>;
type Blake3C = CompressionFunctionFromHasher<Blake3, 2, 32>;

// ************** Rescue Types ***************
type Mds = IntegratedCosetMds<GF, 16>;
type RescuePerm = Rescue<GF, Mds, BasicSboxLayer<GF>, 16>;
type RescueH = PaddingFreeSponge<RescuePerm, 16, 8, 4>;
type RescueC = TruncatedPermutation<RescuePerm, 2, 4, 16>;

fn bench_poseidon2() {
    let perm = PoseidonPerm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixGoldilocks::default(),
        &mut thread_rng(),
    );

    let h = PoseidonH::new(perm.clone());
    let c = PoseidonC::new(perm);

    bench_merkle_tree::<GF, GF, PoseidonH, PoseidonC, 4>(h, c);
}

fn bench_keccak() {
    let h = KeccakH::new(Keccak {});
    let c = KeccakC::new(Keccak {});

    bench_merkle_tree::<GF, u8, KeccakH, KeccakC, 32>(h, c);
}

fn bench_blake3() {
    let h = Blake3H::new(Blake3 {});
    let c = Blake3C::new(Blake3 {});

    bench_merkle_tree::<GF, u8, Blake3H, Blake3C, 32>(h, c);
}

fn bench_rescue() {
    let mds = Mds::default();

    let round_constants = RescuePerm::get_round_constants_from_rng(8, &mut thread_rng());
    let perm = RescuePerm::new(8, round_constants, mds, BasicSboxLayer::for_alpha(7));

    let h = RescueH::new(perm.clone());
    let c = RescueC::new(perm);

    bench_merkle_tree::<GF, GF, RescueH, RescueC, 4>(h, c);
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

    println!("Merkle tree built in {:?}", elapsed);
}

fn main() {
    init_logger();

    println!("\n * Poseidon2");
    estimate_commitment_time(LEVEL_N, "Poseidon2", "Poseidon2", "Goldilocks");
    bench_poseidon2();

    println!("\n * Keccak");
    estimate_commitment_time(LEVEL_N, "Keccak", "Keccak", "Goldilocks");
    bench_keccak();

    println!("\n * Blake3");
    estimate_commitment_time(LEVEL_N, "Blake3", "Blake3", "Goldilocks");
    bench_blake3();

    println!("\n * Rescue");
    estimate_commitment_time(LEVEL_N, "Rescue", "Rescue", "Goldilocks");
    bench_rescue();

    println!("");

    estimate_commitment_time(LEVEL_N, "Poseidon2", "Poseidon2", "Goldilocks");
    estimate_commitment_time(LEVEL_N, "Blake3", "Poseidon2", "Goldilocks");
}

pub fn init_logger() {
    let _ = env_logger::builder().format_timestamp(None).try_init();
}
