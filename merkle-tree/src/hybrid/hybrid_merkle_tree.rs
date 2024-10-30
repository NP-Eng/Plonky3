use alloc::vec;
use alloc::vec::Vec;
use core::array;
use core::cmp::Reverse;
use core::marker::PhantomData;

use itertools::Itertools;
use p3_field::PackedValue;
use p3_matrix::Matrix;
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicHasher, Hash};
use serde::{Deserialize, Serialize};
use tracing::instrument;

use crate::{unpack_array, HybridPseudoCompressionFunction};

/// A binary Merkle tree for packed data. It has leaves of type `F` and digests of type
/// `[W; DIGEST_ELEMS]`.
///
/// This generally shouldn't be used directly. If you're using a Merkle tree as an MMCS,
/// see `MerkleTreeMmcs`.
#[derive(Debug, Serialize, Deserialize)]
pub struct HybridMerkleTree<F, W, M, const DIGEST_ELEMS: usize> {
    pub(crate) leaves: Vec<M>,
    // Enable serialization for this type whenever the underlying array type supports it (len 1-32).
    #[serde(bound(serialize = "[W; DIGEST_ELEMS]: Serialize"))]
    // Enable deserialization for this type whenever the underlying array type supports it (len 1-32).
    #[serde(bound(deserialize = "[W; DIGEST_ELEMS]: Deserialize<'de>"))]
    pub(crate) digest_layers: Vec<Vec<[W; DIGEST_ELEMS]>>,
    _phantom: PhantomData<F>,
}

impl<F: Clone + Send + Sync, W: Clone, M: Matrix<F>, const DIGEST_ELEMS: usize>
    HybridMerkleTree<F, W, M, DIGEST_ELEMS>
{
    /// Matrix heights need not be powers of two. However, if the heights of two given matrices
    /// round up to the same power of two, they must be equal.
    #[instrument(name = "build merkle tree", level = "debug", skip_all,
                 fields(dimensions = alloc::format!("{:?}", leaves.iter().map(|l| l.dimensions()).collect::<Vec<_>>())))]
    pub fn new<P, PW, H, C>(h: &H, c: &C, leaves: Vec<M>) -> Self
    where
        P: PackedValue<Value = F>,
        PW: PackedValue<Value = W>,
        H: CryptographicHasher<F, [W; DIGEST_ELEMS]>,
        H: CryptographicHasher<P, [PW; DIGEST_ELEMS]>,
        H: Sync,
        C: HybridPseudoCompressionFunction<[W; DIGEST_ELEMS], 2>,
        C: HybridPseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>,
        C: Sync,
    {
        assert!(!leaves.is_empty(), "No matrices given?");

        assert_eq!(P::WIDTH, PW::WIDTH, "Packing widths must match");

        let mut leaves_largest_first = leaves
            .iter()
            .sorted_by_key(|l| Reverse(l.height()))
            .peekable();

        // check height property
        assert!(
            leaves_largest_first
                .clone()
                .map(|m| m.height())
                .tuple_windows()
                .all(|(curr, next)| curr == next
                    || curr.next_power_of_two() != next.next_power_of_two()),
            "matrix heights that round up to the same power of two must be equal"
        );

        let sizes = leaves_largest_first
            .clone()
            .map(|m| m.height().next_power_of_two())
            .collect_vec();

        let max_height = leaves_largest_first.peek().unwrap().height();
        let tallest_matrices = leaves_largest_first
            .peeking_take_while(|m| m.height() == max_height)
            .collect_vec();

        let mut digest_layers = vec![first_digest_layer::<P, PW, H, M, DIGEST_ELEMS>(
            h,
            tallest_matrices,
        )];
        loop {
            let prev_layer = digest_layers.last().unwrap().as_slice();
            if prev_layer.len() == 1 {
                break;
            }
            let next_layer_len = prev_layer.len() / 2;

            // The matrices that get injected at this layer.
            let matrices_to_inject = leaves_largest_first
                .peeking_take_while(|m| m.height().next_power_of_two() == next_layer_len)
                .collect_vec();

            let next_digests = compress_and_inject::<P, PW, H, C, M, DIGEST_ELEMS>(
                prev_layer,
                matrices_to_inject,
                h,
                c,
                &sizes,
            );
            digest_layers.push(next_digests);
        }

        Self {
            leaves,
            digest_layers,
            _phantom: PhantomData,
        }
    }

    #[must_use]
    pub fn root(&self) -> Hash<F, W, DIGEST_ELEMS>
    where
        W: Copy,
    {
        self.digest_layers.last().unwrap()[0].into()
    }
}

#[instrument(name = "first digest layer", level = "debug", skip_all)]
fn first_digest_layer<P, PW, H, M, const DIGEST_ELEMS: usize>(
    h: &H,
    tallest_matrices: Vec<&M>,
) -> Vec<[PW::Value; DIGEST_ELEMS]>
where
    P: PackedValue,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]>,
    H: CryptographicHasher<P, [PW; DIGEST_ELEMS]>,
    H: Sync,
    M: Matrix<P::Value>,
{
    let width = PW::WIDTH;
    let max_height = tallest_matrices[0].height();
    let max_height_padded = max_height.next_power_of_two();

    let default_digest: [PW::Value; DIGEST_ELEMS] = [PW::Value::default(); DIGEST_ELEMS];
    let mut digests = vec![default_digest; max_height_padded];

    digests[0..max_height]
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(i, digests_chunk)| {
            let first_row = i * width;
            let packed_digest: [PW; DIGEST_ELEMS] = h.hash_iter(
                tallest_matrices
                    .iter()
                    .flat_map(|m| m.vertically_packed_row(first_row)),
            );
            for (dst, src) in digests_chunk.iter_mut().zip(unpack_array(packed_digest)) {
                *dst = src;
            }
        });

    // If our packing width did not divide max_height, fall back to single-threaded scalar code
    // for the last bit.
    #[allow(clippy::needless_range_loop)]
    for i in (max_height / width * width)..max_height {
        digests[i] = h.hash_iter(tallest_matrices.iter().flat_map(|m| m.row(i)));
    }

    // Everything has been initialized so we can safely cast.
    digests
}

/// Compress `n` digests from the previous layer into `n/2` digests, while potentially mixing in
/// some leaf data, if there are input matrices with (padded) height `n/2`.
fn compress_and_inject<P, PW, H, C, M, const DIGEST_ELEMS: usize>(
    prev_layer: &[[PW::Value; DIGEST_ELEMS]],
    matrices_to_inject: Vec<&M>,
    h: &H,
    c: &C,
    sizes: &[usize],
) -> Vec<[PW::Value; DIGEST_ELEMS]>
where
    P: PackedValue,
    PW: PackedValue,
    H: CryptographicHasher<P::Value, [PW::Value; DIGEST_ELEMS]>,
    H: CryptographicHasher<P, [PW; DIGEST_ELEMS]>,
    H: Sync,
    C: HybridPseudoCompressionFunction<[PW::Value; DIGEST_ELEMS], 2>,
    C: HybridPseudoCompressionFunction<[PW; DIGEST_ELEMS], 2>,
    C: Sync,
    M: Matrix<P::Value>,
{
    let prev_len = prev_layer.len();

    if matrices_to_inject.is_empty() {
        return compress::<PW, C, DIGEST_ELEMS>(prev_layer, c, sizes, prev_len);
    }

    let width = PW::WIDTH;
    let next_len = matrices_to_inject[0].height();
    let next_len_padded = prev_layer.len() / 2;

    let default_digest: [PW::Value; DIGEST_ELEMS] = [PW::Value::default(); DIGEST_ELEMS];
    let mut next_digests = vec![default_digest; next_len_padded];

    next_digests[0..next_len]
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(i, digests_chunk)| {
            let first_row = i * width;
            let left = array::from_fn(|j| PW::from_fn(|k| prev_layer[2 * (first_row + k)][j]));
            let right = array::from_fn(|j| PW::from_fn(|k| prev_layer[2 * (first_row + k) + 1][j]));

            let mut packed_digest = c.compress([left, right], sizes, prev_len);
            let tallest_digest = h.hash_iter(
                matrices_to_inject
                    .iter()
                    .flat_map(|m| m.vertically_packed_row(first_row)),
            );
            packed_digest = c.compress([packed_digest, tallest_digest], sizes, prev_len);
            for (dst, src) in digests_chunk.iter_mut().zip(unpack_array(packed_digest)) {
                *dst = src;
            }
        });

    // If our packing width did not divide next_len, fall back to single-threaded scalar code
    // for the last bit.
    for i in (next_len / width * width)..next_len {
        let left = prev_layer[2 * i];
        let right = prev_layer[2 * i + 1];
        let digest = c.compress([left, right], sizes, prev_len);
        let rows_digest = h.hash_iter(matrices_to_inject.iter().flat_map(|m| m.row(i)));
        next_digests[i] = c.compress([digest, rows_digest], sizes, prev_len);
    }

    // At this point, we've exceeded the height of the matrices to inject, so we continue the
    // process above except with default_digest in place of an input digest.
    for i in next_len..next_len_padded {
        let left = prev_layer[2 * i];
        let right = prev_layer[2 * i + 1];
        let digest = c.compress([left, right], sizes, prev_len);
        next_digests[i] = c.compress([digest, default_digest], sizes, prev_len);
    }

    next_digests
}

/// Compress `n` digests from the previous layer into `n/2` digests.
fn compress<P, C, const DIGEST_ELEMS: usize>(
    prev_layer: &[[P::Value; DIGEST_ELEMS]],
    c: &C,
    sizes: &[usize],
    current_size: usize,
) -> Vec<[P::Value; DIGEST_ELEMS]>
where
    P: PackedValue,
    C: HybridPseudoCompressionFunction<[P::Value; DIGEST_ELEMS], 2>,
    C: HybridPseudoCompressionFunction<[P; DIGEST_ELEMS], 2>,
    C: Sync,
{
    debug_assert!(prev_layer.len().is_power_of_two());
    let width = P::WIDTH;
    let next_len = prev_layer.len() / 2;

    let default_digest: [P::Value; DIGEST_ELEMS] = [P::Value::default(); DIGEST_ELEMS];
    let mut next_digests = vec![default_digest; next_len];

    next_digests[0..next_len]
        .par_chunks_exact_mut(width)
        .enumerate()
        .for_each(|(i, digests_chunk)| {
            let first_row = i * width;
            let left = array::from_fn(|j| P::from_fn(|k| prev_layer[2 * (first_row + k)][j]));
            let right = array::from_fn(|j| P::from_fn(|k| prev_layer[2 * (first_row + k) + 1][j]));
            let packed_digest = c.compress([left, right], sizes, current_size);
            for (dst, src) in digests_chunk.iter_mut().zip(unpack_array(packed_digest)) {
                *dst = src;
            }
        });

    // If our packing width did not divide next_len, fall back to single-threaded scalar code
    // for the last bit.
    for i in (next_len / width * width)..next_len {
        let left = prev_layer[2 * i];
        let right = prev_layer[2 * i + 1];
        let digest = c.compress([left, right], sizes, current_size);
        next_digests[i] = digest;
    }

    // Everything has been initialized so we can safely cast.
    next_digests
}
