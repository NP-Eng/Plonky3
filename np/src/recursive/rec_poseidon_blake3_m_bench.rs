use std::time::Instant;

use p3_blake3::Blake3;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_circle::CirclePcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_mersenne_31::Mersenne31;
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::{prove, verify, StarkConfig};
use p3_poseidon2::Poseidon2ExternalMatrixGeneral;
use p3_monty_31::GenericDiffusionMatrixMontyField31;
use rand::random;
use core::marker::PhantomData;

//
//
//          NOT COMPILING
//
//

#[path = "../common.rs"]
mod common;

use common::{fri_config_str, N_REC_HASHES};

type M31 = Mersenne31;
// TODO 3 or 4? different examples use different values
type Challenge = BinomialExtensionField<M31, 3>;

type ByteHash = Blake3;
type Hasher = SerializingHasher32<ByteHash>;
type Compressor = CompressionFunctionFromHasher<ByteHash, 2, 32>;

type ValMMCS = MerkleTreeMmcs<M31, u8, Hasher, Compressor, 32>;
type ValMmcs = MerkleTreeMmcs<
        [M31; VECTOR_LEN],
        [u64; VECTOR_LEN],
        Hasher,
        Compressor,
        4,
    >;
type ChallengeMMCS = ExtensionMmcs<M31, Challenge, ValMMCS>;
type Challenger = SerializingChallenger32<M31, HashChallenger<u8, ByteHash, 32>>;
type PCS = TwoAdicFriPcs<M31, Dft, ValMmcs, ChallengeMMCS>;
type FullStarkConfig = StarkConfig<PCS, Challenge, Challenger>;
type MdsLight = Poseidon2ExternalMatrixGeneral;
type Diffusion =
        GenericDiffusionMatrixMontyField31<PoseidonParameters, PoseidonDiffusionMatrixParameters>;

const WIDTH: usize = 16;
const SBOX_DEGREE: usize = 3;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 20;

const NUM_ROWS: usize = 1 << 15;
const VECTOR_LEN: usize = 1 << 3;
const NUM_PERMUTATIONS: usize = NUM_ROWS * VECTOR_LEN;

#[cfg(feature = "parallel")]
type Dft = p3_dft::Radix2DitParallel;
#[cfg(not(feature = "parallel"))]
type Dft = p3_dft::Radix2Bowers;

fn main() {
    
    let byte_hash = ByteHash {};
    let field_hash = Hasher::new(byte_hash);
    let compress = Compressor::new(byte_hash);
    let val_mmcs = ValMMCS::new(field_hash, compress);
    let challenge_mmcs = ChallengeMMCS::new(val_mmcs.clone());

    // Poseidon parameters
    let external_linear_layer = MdsLight {};
    let internal_linear_layer = Diffusion::new();
    let constants = RoundConstants::from_rng(&mut thread_rng());

    let inputs = (0..NUM_PERMUTATIONS).map(|_| random()).collect::<Vec<_>>();
    let trace = generate_vectorized_trace_rows::<
        Val,
        MdsLight,
        Diffusion,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
        VECTOR_LEN,
    >(
        inputs,
        &constants,
        &external_linear_layer,
        &internal_linear_layer,
    );

    let dft = Dft {};

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 84,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    
    // Need to print this here as FriConfig isn't Clone and the next assignment
    // consumes it
    println!("Recursive Keccak 512 bits to 256 bits over Mersenne31 using Blake3 ({N_REC_HASHES} inputs)");
    println!("  FRI config: {}", fri_config_str(&fri_config));

    let pcs = PCS::new(dft, val_mmcs, fri_config);

    let config = FullStarkConfig::new(pcs);

    let inputs = (0..N_REC_HASHES).map(|_| random()).collect::<Vec<_>>();

    let time = Instant::now();
    let trace = generate_trace_rows::<M31>(inputs);
    let elapsed = time.elapsed();

    println!("  Time to generate the trace: {:?}", elapsed);
    println!("    per input [u64; 25]: {:?}", elapsed / N_REC_HASHES as u32);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);

    let time = Instant::now();
    let proof = prove(&config, &air, &mut challenger, trace, &vec![]);
    let elapsed = time.elapsed();

    println!("  Proving time: {:?}", elapsed);
    println!("    per input [u64; 25]: {:?}", elapsed / N_REC_HASHES as u32);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);

    let time = Instant::now();
    verify(&config, &air, &mut challenger, &proof, &vec![]).unwrap();
    let elapsed = time.elapsed();

    println!("  Verification time: {:?}", elapsed);
    println!("    per input [u64; 25]: {:?}", elapsed / N_REC_HASHES as u32);
}
