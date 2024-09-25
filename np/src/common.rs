use std::time::Duration;

pub(crate) const N_ITERS: usize = 1 << 13;

const VERBOSE: bool = true;

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

// A's machine
// Leaf digest times in nanoseconds
const DIGEST_TIMES: [(&str, usize); 4] = [
    ("Poseidon2", 41000),
    ("Keccak", 15500),
    ("Blake3", 3100),
    ("Rescue", 227500),
];

// Two-to-one compression times in nanoseconds
const COMPRESSION_TIMES: [(&str, usize); 4] = [
    ("Poseidon2", 39700),
    ("Keccak", 16800),
    ("Blake3", 3800),
    ("Rescue", 227800),
];

fn get_digest_time(hash: &str) -> usize {
    DIGEST_TIMES.iter().find(|(h, _)| *h == hash).unwrap().1
}

fn get_compression_time(hash: &str) -> usize {
    COMPRESSION_TIMES.iter().find(|(h, _)| *h == hash).unwrap().1
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
) -> usize {
    let time_h1 = get_compression_time(h1);
    let time_h2 = get_compression_time(h2);
    
    let time_digest = (1 << n) * get_digest_time(hd);
    let time_compress = ((1 << n) - (1 << m)) * time_h1 + ((1 << m) - (1 << k)) * time_h2;

    let time = time_digest + time_compress;

    if VERBOSE {
        println!(
            "Estimating commitment time for n={n}, m={m}, k={k}, hd={hd}, h1={h1}, h2={h2}",
        );

        let human_readable_time = Duration::from_nanos(time as u64);
        println!("Estimate: {:?}", human_readable_time);
    }

    time
}

pub(crate) fn estimate_commitment_time_mixed(n: usize, m: usize, hd: &str, h1: &str, h2: &str) -> usize {
    estimate_commitment_time_mixed_capped(n, m, 0, hd, h1, h2)
}

pub(crate) fn estimate_commitment_time_capped(n: usize, k: usize, hd: &str, h: &str) -> usize {
    estimate_commitment_time_mixed_capped(n, k, k, hd, h, h)
}

pub(crate) fn estimate_commitment_time(n: usize, hd: &str, h: &str) -> usize {
    estimate_commitment_time_mixed_capped(n, 0, 0, hd, h, h)
}

pub(crate) fn estimate_verification_time_mixed_capped(
    n: usize,
    m: usize,
    k: usize,
    h1: &str,
    h2: &str,
) -> usize {
    // Add leaf digest time
    todo!();
    let time_h1 = get_compression_time(h1);
    let time_h2 = get_compression_time(h2);
    (n - m) * time_h1 + (m - k) * time_h2
}

pub(crate) fn estimate_verification_time_mixed(n: usize, m: usize, h1: &str, h2: &str) -> usize {
    estimate_verification_time_mixed_capped(n, m, 0, h1, h2)
}

pub(crate) fn estimate_verification_time_capped(n: usize, k: usize, h: &str) -> usize {
    estimate_verification_time_mixed_capped(n, k, k, h, h)
}

pub(crate) fn estimate_verification_time(n: usize, h: &str) -> usize {
    estimate_verification_time_mixed_capped(n, 0, 0, h, h)
}

#[cfg(test)]
#[test]
fn test_estimator() {
    assert_eq!(
        estimate_commitment_time_capped(28, 4, "Poseidon", "Poseidon"),
        estimate_commitment_time_mixed_capped(28, 28, 4, "Poseidon", "Poseidon", "Poseidon"),
    );
}
