use core::marker::PhantomData;
use std::time::Instant;

use p3_blake3::Blake3;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_fri::FriConfig;
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher32};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::random;

#[path = "../common.rs"]
mod common;

use common::{fri_config_str, N_REC_HASHES};

type M31 = Mersenne31;
type Challenge = BinomialExtensionField<M31, 3>;

type ByteHash = Blake3;
type Hasher = SerializingHasher32<ByteHash>;
type Compressor = CompressionFunctionFromHasher<ByteHash, 2, 32>;
type ValMMCS = MerkleTreeMmcs<M31, u8, Hasher, Compressor, 32>;
type ChallengeMMCS = ExtensionMmcs<M31, Challenge, ValMMCS>;
type Challenger = SerializingChallenger32<M31, HashChallenger<u8, ByteHash, 32>>;
type PCS = CirclePcs<M31, ValMMCS, ChallengeMMCS>;
type FullStarkConfig = StarkConfig<PCS, Challenge, Challenger>;

fn main() {
    let byte_hash = ByteHash {};
    let field_hash = Hasher::new(byte_hash);
    let compress = Compressor::new(byte_hash);
    let val_mmcs = ValMMCS::new(field_hash, compress);
    let challenge_mmcs = ChallengeMMCS::new(val_mmcs.clone());

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

    let pcs = PCS {
        mmcs: val_mmcs,
        fri_config,
        _phantom: PhantomData,
    };

    let config = FullStarkConfig::new(pcs);

    let inputs = (0..N_REC_HASHES).map(|_| random()).collect::<Vec<_>>();

    let time = Instant::now();
    let trace = generate_trace_rows::<M31>(inputs);
    let elapsed = time.elapsed();

    println!("  Time to generate the trace: {:?}", elapsed);
    println!(
        "    per input [u64; 25]: {:?}",
        elapsed / N_REC_HASHES as u32
    );

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);

    let time = Instant::now();
    let proof = prove(&config, &KeccakAir {}, &mut challenger, trace, &vec![]);
    let elapsed = time.elapsed();

    println!("  Proving time: {:?}", elapsed);
    println!(
        "    per input [u64; 25]: {:?}",
        elapsed / N_REC_HASHES as u32
    );

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);

    let time = Instant::now();
    verify(&config, &KeccakAir {}, &mut challenger, &proof, &vec![]).unwrap();
    let elapsed = time.elapsed();

    println!("  Verification time: {:?}", elapsed);
    println!(
        "    per input [u64; 25]: {:?}",
        elapsed / N_REC_HASHES as u32
    );
}
