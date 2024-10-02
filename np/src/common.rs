#![allow(unused)]

use std::time::Duration;

use p3_fri::FriConfig;

pub(crate) const N_ITERS: usize = 1 << 16;

// log2 of the number of leaves
pub(crate) const LEVEL_N: usize = 3;
// log2 of the number of caps
pub(crate) const LEVEL_K: usize = 0;

// pub(crate) const N_REC_HASHES: usize = 1365;
pub(crate) const N_REC_HASHES: usize = 1 << 15;

const VERBOSE: bool = false;

/*
// Leaf digest times in nanoseconds
const DIGEST_TIMES: [(&str, usize); 4] = [
    ("Poseidon2", 38000),
    ("Keccak", 21500),
    ("Blake3", 1100),
    ("Rescue", 241000),
];

// Two-to-one compression times in nanoseconds
const COMPRESSION_TIMES: [(&str, usize); 4] = [
    ("Poseidon2", 38000),
    ("Keccak", 21500),
    ("Blake3", 1100),
    ("Rescue", 241000),
];
*/

// // A's machine (--release)
// // Leaf digest times in nanoseconds
// const DIGEST_TIMES: [(&str, usize); 4] = [
//     ("Poseidon2", 2600),
//     ("Keccak", 700),
//     ("Blake3", 360),
//     ("Rescue", 24600),
// ];

// // Two-to-one compression times in nanoseconds
// const COMPRESSION_TIMES: [(&str, usize); 4] = [
//     ("Poseidon2", 1400),
//     ("Keccak", 550),
//     ("Blake3", 320),
//     ("Rescue", 21800),
// ];

// A's machine (without --release)
// Leaf digest times in nanoseconds
const DIGEST_TIMES: [(&str, &str, usize); 8] = [
    ("Poseidon2", "Goldilocks", 41000),
    ("Keccak", "Goldilocks", 15500),
    ("Blake3", "Goldilocks", 3100),
    ("Rescue", "Goldilocks", 227500),
    ("Poseidon2", "Mersenne31", 28300),
    ("Keccak", "Mersenne31", 14600),
    ("Blake3", "Mersenne31", 2300),
    ("Rescue", "Mersenne31", 138800),
];

// Two-to-one compression times in nanoseconds
const COMPRESSION_TIMES: [(&str, &str, usize); 8] = [
    ("Poseidon2", "Goldilocks", 40500),
    ("Keccak", "Goldilocks", 16800),
    ("Blake3", "Goldilocks", 3800),
    ("Rescue", "Goldilocks", 225800),
    ("Poseidon2", "Mersenne31", 28200),
    ("Keccak", "Mersenne31", 16900),
    ("Blake3", "Mersenne31", 3900),
    ("Rescue", "Mersenne31", 137400),
];

// Time to prove a single hash execution recursively (per input)
const REC_HASH_PROVING_TIMES: [(&str, &str, &str, usize); 3] = [
    ("Keccak", "Blake3", "Mersenne31", 354300),
    ("Keccak", "Poseidon2", "KoalaBear", 960700),
    ("Poseidon2", "Poseidon2", "KoalaBear", 238000),
];

// Time to verify a single hash execution recursively (total, as it varies very
// quite sublinearly in the number of inputs)
const REC_HASH_VERIFICATION_TIMES: [(&str, &str, &str, usize); 3] = [
    ("Keccak", "Blake3", "Mersenne31", 573000),
    ("Keccak", "Poseidon2", "KoalaBear", 42530000),
    ("Poseidon2", "Poseidon2", "KoalaBear", 699100000),
];

fn get_digest_time(hash: &str, field: &str) -> usize {
    DIGEST_TIMES
        .iter()
        .find_map(|(h, f, v)| {
            if *h == hash && *f == field {
                Some(*v)
            } else {
                None
            }
        })
        .unwrap()
}

fn get_compression_time(hash: &str, field: &str) -> usize {
    COMPRESSION_TIMES
        .iter()
        .find_map(|(h, f, v)| {
            if *h == hash && *f == field {
                Some(*v)
            } else {
                None
            }
        })
        .unwrap()
}

fn get_or_estimate_rec_hash_proving_time(hash: &str, outer_hash: &str, field: &str) -> usize {
    let (estimator_hash, convert_blake3) = if hash == "Blake3" {
        ("Keccak", true)
    } else {
        (hash, false)
    };

    let time = REC_HASH_PROVING_TIMES
        .iter()
        .find_map(|(h, oh, f, v)| {
            if *h == estimator_hash && *oh == outer_hash && *f == field {
                Some(*v)
            } else {
                None
            }
        })
        .unwrap();

    // Estimate the recursive Blake3 time by assuming recursion slowdown will be
    // proportional to that of Keccak
    if convert_blake3 {
        // TODO obtain native times for (Blake3, KoalaBear) and (Keccak, KoalaBear)
        let tmp_field = if field == "KoalaBear" {
            "Mersenne31"
        } else {
            field
        };

        time * get_digest_time("Blake3", tmp_field) / get_digest_time("Keccak", tmp_field)
    } else {
        time
    }
}

fn get_or_estimate_rec_hash_verification_time(hash: &str, outer_hash: &str, field: &str) -> usize {
    let (estimator_hash, convert_blake3) = if hash == "Blake3" {
        ("Keccak", true)
    } else {
        (hash, false)
    };

    let time = REC_HASH_VERIFICATION_TIMES
        .iter()
        .find_map(|(h, oh, f, v)| {
            if *h == estimator_hash && *f == field && *oh == outer_hash {
                Some(*v)
            } else {
                None
            }
        })
        .unwrap();

    // Estimate the recursive Blake3 time by assuming recursion slowdown will be
    // proportional to that of Keccak
    if convert_blake3 {
        // TODO obtain native times for (Blake3, KoalaBear) and (Keccak, KoalaBear)
        let tmp_field = if field == "KoalaBear" {
            "Mersenne31"
        } else {
            field
        };

        time * get_digest_time("Blake3", tmp_field) / get_digest_time("Keccak", tmp_field)
    } else {
        time
    }
}

// n: level of the leaves (i.e. the number of leaves is 2^n)
// m: level where the switch to h1 happens (already computed with h1)
// k: level of the caps
// hd: time to digest a leaf
// h1: time to compress two nodes into one with the first hash function
// h2: time to compress two nodes into one with the second hash function
// Returns the estimated running time in ns
pub(crate) fn estimate_commitment_time_mixed_capped(
    n: usize,
    m: usize,
    k: usize,
    hd: &str,
    h1: &str,
    h2: &str,
    field: &str,
) -> usize {
    let time_h1 = get_compression_time(h1, field);
    let time_h2 = get_compression_time(h2, field);

    let time_digest = (1 << n) * get_digest_time(hd, field);
    let time_compress = ((1 << n) - (1 << m)) * time_h1 + ((1 << m) - (1 << k)) * time_h2;

    let time = time_digest + time_compress;

    if VERBOSE {
        println!(
            "Estimating commitment time for n={n}, m={m}, k={k}, hd={hd}, h1={h1}, h2={h2} over the field {field}",
        );

        let human_readable_time = Duration::from_nanos(time as u64);
        println!("Estimate: {:?}", human_readable_time);
    }

    time
}

pub(crate) fn estimate_commitment_time_mixed(
    n: usize,
    m: usize,
    hd: &str,
    h1: &str,
    h2: &str,
    field: &str,
) -> usize {
    estimate_commitment_time_mixed_capped(n, m, 0, hd, h1, h2, field)
}

pub(crate) fn estimate_commitment_time_capped(
    n: usize,
    k: usize,
    hd: &str,
    h: &str,
    field: &str,
) -> usize {
    estimate_commitment_time_mixed_capped(n, k, k, hd, h, h, field)
}

pub(crate) fn estimate_commitment_time(n: usize, hd: &str, h: &str, field: &str) -> usize {
    estimate_commitment_time_mixed_capped(n, 0, 0, hd, h, h, field)
}

pub(crate) fn estimate_verification_time_mixed_capped(
    n: usize,
    m: usize,
    k: usize,
    hd: &str,
    h1: &str,
    h2: &str,
    field: &str,
) -> usize {
    let time_digest = get_digest_time(hd, field);
    let time_h1 = get_compression_time(h1, field);
    let time_h2 = get_compression_time(h2, field);

    time_digest + (n - m) * time_h1 + (m - k) * time_h2
}

pub(crate) fn estimate_verification_time_mixed(
    n: usize,
    m: usize,
    hd: &str,
    h1: &str,
    h2: &str,
    field: &str,
) -> usize {
    estimate_verification_time_mixed_capped(n, m, 0, hd, h1, h2, field)
}

pub(crate) fn estimate_verification_time_capped(
    n: usize,
    k: usize,
    hd: &str,
    h: &str,
    field: &str,
) -> usize {
    estimate_verification_time_mixed_capped(n, k, k, hd, h, h, field)
}

pub(crate) fn estimate_verification_time(n: usize, hd: &str, h: &str, field: &str) -> usize {
    estimate_verification_time_mixed_capped(n, 0, 0, hd, h, h, field)
}

pub(crate) fn estimate_recursive_path_proving_time_mixed_capped(
    n: usize,
    m: usize,
    k: usize,
    hd: &str, // leaf digest hash
    h1: &str, // bottom-layers inner hash
    h2: &str, // non-bottom-layers inner hash
    oh: &str, // outer hash
    field: &str,
) -> usize {
    // Add leaf digest time
    let time_digest = get_or_estimate_rec_hash_proving_time(hd, oh, field);
    let time_h1 = get_or_estimate_rec_hash_proving_time(h1, oh, field);
    let time_h2 = get_or_estimate_rec_hash_proving_time(h2, oh, field);

    if VERBOSE {
        println!("Formula: time_digest + (n - m) * time_h1 + (m - k) * time_h2");
        println!(
            "Values: {} + ({} - {}) * {} + ({} - {}) * {}",
            time_digest, n, m, time_h1, m, k, time_h2
        );
    }

    time_digest + (n - m) * time_h1 + (m - k) * time_h2
}

pub(crate) fn estimate_recursive_path_proving_time_mixed(
    n: usize,
    m: usize,
    hd: &str,
    h1: &str,
    h2: &str,
    oh: &str,
    field: &str,
) -> usize {
    estimate_recursive_path_proving_time_mixed_capped(n, m, 0, hd, h1, h2, oh, field)
}

pub(crate) fn estimate_recursive_path_proving_time_capped(
    n: usize,
    k: usize,
    hd: &str,
    h: &str,
    oh: &str,
    field: &str,
) -> usize {
    estimate_recursive_path_proving_time_mixed_capped(n, k, k, hd, h, h, oh, field)
}

pub(crate) fn estimate_recursive_path_proving_time(
    n: usize,
    hd: &str,
    h: &str,
    oh: &str,
    field: &str,
) -> usize {
    estimate_recursive_path_proving_time_mixed_capped(n, 0, 0, hd, h, h, oh, field)
}

pub(crate) fn fri_config_str<M>(fri_config: &FriConfig<M>) -> String {
    format!(
        "log_blowup: {}, num_queries: {}, proof_of_work_bits: {}",
        fri_config.log_blowup, fri_config.num_queries, fri_config.proof_of_work_bits
    )
}

#[cfg(test)]
#[test]
fn test_estimator() {
    assert_eq!(
        estimate_commitment_time_capped(28, 4, "Poseidon", "Poseidon", "Goldilocks"),
        estimate_commitment_time_mixed_capped(
            28,
            28,
            4,
            "Poseidon",
            "Poseidon",
            "Poseidon",
            "Goldilocks"
        ),
    );
}
