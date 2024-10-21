use p3_baby_bear::{BabyBear, BabyBearParameters, DiffusionMatrixBabyBear};
use p3_blake3::Blake3;
use p3_field::{AbstractField, Field, PackedValue};
use p3_merkle_tree::{
    HybridPseudoCompressionFunction, NodeConverter256BabyBearBytes, SimpleHybridCompressor,
};
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, PaddingFreeSponge, SerializingHasher32,
    TruncatedPermutation,
};
use rand::thread_rng;

type PermPoseidon =
    Poseidon2<BabyBear, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
type HPoseidon = PaddingFreeSponge<PermPoseidon, 16, 8, 8>;
type CPoseidon = TruncatedPermutation<PermPoseidon, 2, 8, 16>;

type HBlake3 = SerializingHasher32<Blake3>;
type CBlake3 = CompressionFunctionFromHasher<Blake3, 2, 32>;

fn main() {
    let perm_poseidon = PermPoseidon::new_from_rng_128(
        Poseidon2ExternalMatrixGeneral,
        DiffusionMatrixBabyBear::default(),
        &mut thread_rng(),
    );

    let h_poseidon = HPoseidon::new(perm_poseidon.clone());

    let c_poseidon = CPoseidon::new(perm_poseidon);
    let c_blake3 = CBlake3::new(Blake3 {});

    let c_hybrid = SimpleHybridCompressor::<_, _, _, _, 8, 32, NodeConverter256BabyBearBytes>::new(
        c_poseidon, c_blake3,
    );

    let dat1: [BabyBear; 10] = rand::random();
    let dat2: [BabyBear; 10] = rand::random();

    let digest_pair = [h_poseidon.hash_iter(dat1), h_poseidon.hash_iter(dat2)];

    println!(
        "Compression result (H1): {:?}",
        c_hybrid.compress(digest_pair, &[8, 4, 1], 8)
    );
    println!(
        "Compression result (H2): {:?}",
        c_hybrid.compress(digest_pair, &[8, 4, 1], 4)
    );
}

// C: PseudoCompressionFunction<[W; DIGEST_ELEMENTS], 2>

// HC: HybridCompressionFunction<[W; DIGEST_ELEMENTS], 2>

// SimpleHybridCompressor: HybridCompressionFunction<[BabyBear; 8], 2>
// SimpleHybridCompressor: HybridCompressionFunction<[[BabyBear; 8]; WIDTH], 2>

// C: PseudoCompressionFunction<[PW; DIGEST_ELEMENTS], 2>
