//! The blake3 hash function.

// TODO reintroduce NP
// #![no_std]

use p3_symmetric::CryptographicHasher;

/// The blake3 hash function.
#[derive(Copy, Clone, Debug)]
pub struct Blake3;

impl CryptographicHasher<u8, [u8; 32]> for Blake3 {
    fn hash_iter<I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = u8>,
    {
        // TODO clean up
        // let mut count = 0;

        const BUFLEN: usize = 512; // Tweakable parameter; determined by experiment
        let mut hasher = blake3::Hasher::new();
        p3_util::apply_to_chunks::<BUFLEN, _, _>(input, |buf| {
            // TODO remove
            // count += buf.len();

            hasher.update(buf);
        });

        // TODO remove
        // println!("blake3 hash_iter for {} bytes", count);

        hasher.finalize().into()
    }

    fn hash_iter_slices<'a, I>(&self, input: I) -> [u8; 32]
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut hasher = blake3::Hasher::new();
        for chunk in input.into_iter() {
            hasher.update(chunk);
        }
        hasher.finalize().into()
    }
}
