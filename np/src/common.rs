use std::time::Duration;

pub(crate) const N_PAIRS: usize = 2 << 2;

const VERBOSE: bool = true;

// Hashing times in nanoseconds
const HASHING_TIMES: [(&str, usize); 4] = [
    ("Poseidon2", 38000),
    ("Keccak", 21500),
    ("Blake3", 1100),
    ("Rescue", 241000),
];

fn get_hashing_time(hash: &str) -> usize {
    HASHING_TIMES.iter().find(|(h, _)| *h == hash).unwrap().1
}

// n: level of the leaves (i.e. the number of leaves is 2^n)
// m: level where the switch to h1 happens (already computed with h1)
// k: level of the caps
// Returns the estimated running time in ns
pub(crate) fn estimate_commitment_time_mixed_capped(
    n: usize,
    m: usize,
    k: usize,
    h1: &str,
    h2: &str,
) -> usize {
    let time_h1 = get_hashing_time(h1);
    let time_h2 = get_hashing_time(h2);
    let time = ((2 << n) - (2 << m)) * time_h1 + ((2 << m) - (2 << k)) * time_h2;

    if VERBOSE {
        println!(
            "Estimating commitment time for n={}, m={}, k={}, h1={}, h2={}",
            n, m, k, h1, h2
        );

        let human_readable_time = Duration::from_nanos(time as u64);
        println!("Estimate: {:?}", human_readable_time);
    }

    time
}

pub(crate) fn estimate_commitment_time_mixed(n: usize, m: usize, h1: &str, h2: &str) -> usize {
    estimate_commitment_time_mixed_capped(n, m, 0, h1, h2)
}

pub(crate) fn estimate_commitment_time_capped(n: usize, k: usize, h: &str) -> usize {
    estimate_commitment_time_mixed_capped(n, k, k, h, h)
}

pub(crate) fn estimate_commitment_time(n: usize, h: &str) -> usize {
    estimate_commitment_time_mixed_capped(n, 0, 0, h, h)
}

pub(crate) fn estimate_verification_time_mixed_capped(
    n: usize,
    m: usize,
    k: usize,
    h1: &str,
    h2: &str,
) -> usize {
    let time_h1 = get_hashing_time(h1);
    let time_h2 = get_hashing_time(h2);
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
        estimate_commitment_time_capped(28, 4, "Poseidon"),
        estimate_commitment_time_mixed_capped(28, 28, 4, "Poseidon", "Poseidon"),
    );
    // TODO add more
}
