use core::marker::PhantomData;
use std::time::Instant;

use p3_blake3::Blake3;
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_koala_bear::{DiffusionMatrixKoalaBear, KoalaBear};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher32, TruncatedPermutation,
};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::{random, thread_rng};

#[path = "../common.rs"]
mod common;

use common::{fri_config_str, N_REC_HASHES};

type KB = KoalaBear;
type Challenge = BinomialExtensionField<KB, 4>;
type Perm = Poseidon2<KB, Poseidon2ExternalMatrixGeneral, DiffusionMatrixKoalaBear, 16, 3>;
type Hasher = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compressor = TruncatedPermutation<Perm, 2, 8, 16>;
type ValMMCS =
    MerkleTreeMmcs<<KB as Field>::Packing, <KB as Field>::Packing, Hasher, Compressor, 8>;
type ChallengeMMCS = ExtensionMmcs<KB, Challenge, ValMMCS>;
type Challenger = DuplexChallenger<KB, Perm, 16, 8>;
type Dft = Radix2DitParallel;
type PCS = TwoAdicFriPcs<KB, Dft, ValMMCS, ChallengeMMCS>;
type FullStarkConfig = StarkConfig<PCS, Challenge, Challenger>;

fn main() {
    let perm = Perm::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixKoalaBear::default(),
        &mut thread_rng(),
    );
    let hasher = Hasher::new(perm.clone());
    let compressor = Compressor::new(perm.clone());
    let val_mmcs = ValMMCS::new(hasher, compressor);
    let challenge_mmcs = ChallengeMMCS::new(val_mmcs.clone());

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 84,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };

    // Need to print this here as FriConfig isn't Clone and the next assignment
    // consumes it
    println!(
        "Recursive Keccak hash over KoalaBear with outer hash Poseidon2 ({N_REC_HASHES} inputs)"
    );
    println!("  FRI config: {}", fri_config_str(&fri_config));

    let dft = Dft {};
    let pcs = PCS::new(dft, val_mmcs, fri_config);

    let config = FullStarkConfig::new(pcs);

    let inputs = (0..N_REC_HASHES).map(|_| random()).collect::<Vec<_>>();

    let time = Instant::now();
    let trace = generate_trace_rows::<KB>(inputs);
    let elapsed = time.elapsed();

    println!("  Time to generate the trace: {:?}", elapsed);
    println!(
        "    per input [u64; 25]: {:?}",
        elapsed / N_REC_HASHES as u32
    );

    let mut challenger = Challenger::new(perm.clone());

    let time = Instant::now();
    let proof = prove(&config, &KeccakAir {}, &mut challenger, trace, &vec![]);
    let elapsed = time.elapsed();

    println!("  Proving time: {:?}", elapsed);
    println!(
        "    per input [u64; 25]: {:?}",
        elapsed / N_REC_HASHES as u32
    );

    let mut challenger = Challenger::new(perm.clone());

    let time = Instant::now();
    verify(&config, &KeccakAir {}, &mut challenger, &proof, &vec![]).unwrap();
    let elapsed = time.elapsed();

    println!("  Verification time: {:?}", elapsed);
    println!(
        "    per input [u64; 25]: {:?}",
        elapsed / N_REC_HASHES as u32
    );
}
