use std::time::Instant;

use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::Field;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_koala_bear::{
    DiffusionMatrixKoalaBear, KoalaBear, KoalaBearDiffusionMatrixParameters, KoalaBearParameters,
};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_monty_31::GenericDiffusionMatrixMontyField31;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_poseidon2_air::{generate_trace_rows, Poseidon2Air, RoundConstants};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
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
type PCS = TwoAdicFriPcs<KB, Dft, ValMMCS, ChallengeMMCS>;
type FullStarkConfig = StarkConfig<PCS, Challenge, Challenger>;
type MdsLight = Poseidon2ExternalMatrixGeneral;
type Diffusion =
    GenericDiffusionMatrixMontyField31<KoalaBearParameters, KoalaBearDiffusionMatrixParameters>;

const WIDTH: usize = 16;
const SBOX_DEGREE: usize = 3;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 20;

#[cfg(feature = "parallel")]
type Dft = p3_dft::Radix2DitParallel;
#[cfg(not(feature = "parallel"))]
type Dft = p3_dft::Radix2Bowers;

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

    // Poseidon parameters
    let external_linear_layer = MdsLight {};
    let internal_linear_layer = Diffusion::new();
    let constants = RoundConstants::from_rng(&mut thread_rng());

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 84,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };

    // Need to print this here as FriConfig isn't Clone and the next assignment
    // consumes it
    println!(
        "Recursive Poseidon2 hash over KoalaBear with outer hash Poseidon2 ({N_REC_HASHES} inputs)"
    );
    println!("  FRI config: {}", fri_config_str(&fri_config));

    let dft = Dft {};
    let pcs = PCS::new(dft, val_mmcs, fri_config);

    let config = FullStarkConfig::new(pcs);

    let inputs = (0..N_REC_HASHES).map(|_| random()).collect::<Vec<_>>();

    let time = Instant::now();

    let elapsed = time.elapsed();

    println!("  Time to generate the trace: {:?}", elapsed);
    let trace = generate_trace_rows::<
        KB,
        MdsLight,
        Diffusion,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >(
        inputs,
        &constants,
        &external_linear_layer,
        &internal_linear_layer,
    );
    println!("    per input: {:?}", elapsed / N_REC_HASHES as u32);

    let air: Poseidon2Air<
        KB,
        MdsLight,
        Diffusion,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    > = Poseidon2Air::new(constants, external_linear_layer, internal_linear_layer);

    let mut challenger = Challenger::new(perm.clone());

    let time = Instant::now();
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);
    let elapsed = time.elapsed();

    println!("  Proving time: {:?}", elapsed);
    println!("    per input: {:?}", elapsed / N_REC_HASHES as u32);

    let mut challenger = Challenger::new(perm);

    let time = Instant::now();
    verify(&config, &air, &mut challenger, &proof, &vec![]).unwrap();
    let elapsed = time.elapsed();

    println!("  Verification time: {:?}", elapsed);
    println!("    per input: {:?}", elapsed / N_REC_HASHES as u32);
}
