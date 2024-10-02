use std::time::Duration;

use common::estimate_recursive_path_proving_time;

#[path = "../common.rs"]
mod common;

fn main() {
    let n = 20;

    let configs = vec![
        ("Poseidon2", "Poseidon2", "Poseidon2", "KoalaBear"),
        ("Keccak", "Poseidon2", "Poseidon2", "KoalaBear"),
        ("Blake3", "Poseidon2", "Poseidon2", "KoalaBear"),
    ];

    for c in configs {
        let t = estimate_recursive_path_proving_time(n, c.0, c.1, c.2, c.3);
        let t = Duration::from_nanos(t as u64);

        println!("Estimated time to prove a {n}-node path with:");
        println!("  - {} digest", c.0);
        println!("  - {} compression", c.1);
        println!("  - {} outer hash", c.2);
        println!("  - {} as the field", c.3);
        println!("  Estimate: {:?}", t);
    }
}
