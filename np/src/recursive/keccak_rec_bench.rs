use std::fmt::Debug;

use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_goldilocks::Goldilocks;
use p3_keccak::Keccak256Hash;
use p3_keccak_air::{generate_trace_rows, KeccakAir};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher64};
use p3_uni_stark::{prove, verify, StarkConfig};
use rand::random;

#[path = "../common.rs"]
mod common;

use common::N_REC_HASHES;

// Fields
type GF = Goldilocks;
type ChallengeField = BinomialExtensionField<GF, 2>;

// Hashing types
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher64<ByteHash>;
type KeccakC = CompressionFunctionFromHasher<ByteHash, 2, 32>;

// Commitment schemes
type GFMmcs = MerkleTreeMmcs<GF, u8, FieldHash, KeccakC, 32>;
type ChallengeFieldMmcs = ExtensionMmcs<GF, ChallengeField, GFMmcs>;
type PCS = TwoAdicFriPcs<GF, Radix2DitParallel, GFMmcs, ChallengeFieldMmcs>;

// Challenger
type Challenger = SerializingChallenger64<GF, HashChallenger<u8, ByteHash, 32>>;

fn main() {
    let byte_hash = ByteHash {};
    let hasher = FieldHash::new(byte_hash);
    let compress = KeccakC::new(byte_hash);

    let val_mmcs = GFMmcs::new(hasher, compress);
    let challenge_mmcs = ChallengeFieldMmcs::new(val_mmcs.clone());

    let dft = Radix2DitParallel {};

    let inputs = (0..N_REC_HASHES).map(|_| random()).collect::<Vec<_>>();
    let trace = generate_trace_rows::<GF>(inputs);

    let fri_config = FriConfig {
        log_blowup: 1,
        num_queries: 84,
        proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };

    let pcs = PCS::new(dft, val_mmcs, fri_config);

    type MyConfig = StarkConfig<PCS, ChallengeField, Challenger>;
    let config = MyConfig::new(pcs);

    let mut challenger = Challenger::from_hasher(vec![], byte_hash);

    let start = std::time::Instant::now();
    let proof = prove(&config, &KeccakAir {}, &mut challenger, trace, &vec![]);
    let elapsed = start.elapsed();

    println!("Keccak 512 bits to 256 bits");
    println!("\t{N_REC_HASHES} hashes");
    println!("\tTime: {:?}", elapsed);
    println!("\tTime per iteration: {:?}", elapsed / N_REC_HASHES as u32);

    // let mut challenger = Challenger::from_hasher(vec![], byte_hash);
    // verify(&config, &KeccakAir {}, &mut challenger, &proof, &vec![])
}
