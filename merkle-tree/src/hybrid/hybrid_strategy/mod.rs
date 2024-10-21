use core::marker::PhantomData;

use p3_symmetric::PseudoCompressionFunction;

mod node_converter;

pub use node_converter::*;

// TODO add to doc: closely mimics CryptographicHasher but

// TODO decide if converting the input to a reference brings about performance
// improvements or at least doesn't incur overhead
trait NodeConverter<N1, N2> {
    fn to_n2(n1: N1) -> N2;

    fn to_n1(n2: N2) -> N1;
}

pub trait HybridPseudoCompressionFunction<T, const N: usize>: Clone {
    fn compress(&self, input: [T; N], sizes: &[usize], current_size: usize) -> T;
}

#[derive(Clone)]
pub struct SimpleHybridCompressor<
    C1,
    C2,
    W1,
    W2,
    const DIGEST_ELEMS_1: usize,
    const DIGEST_ELEMS_2: usize,
    NC,
> where
    C1: Clone,
    C2: Clone,
    W1: Clone,
    W2: Clone,
    NC: Clone,
{
    c1: C1,
    c2: C2,
    _marker: PhantomData<(W1, W2, NC)>,
}

impl<C1, C2, W1, W2, NC, const DIGEST_ELEMS_1: usize, const DIGEST_ELEMS_2: usize>
    SimpleHybridCompressor<C1, C2, W1, W2, DIGEST_ELEMS_1, DIGEST_ELEMS_2, NC>
where
    C1: Clone,
    C2: Clone,
    NC: Clone,
    W1: Clone,
    W2: Clone,
{
    pub fn new(c1: C1, c2: C2) -> Self {
        Self {
            c1,
            c2,
            _marker: PhantomData,
        }
    }
}

impl<C1, C2, W1, W2, NC, const DIGEST_ELEMS_1: usize, const DIGEST_ELEMS_2: usize>
    HybridPseudoCompressionFunction<[W1; DIGEST_ELEMS_1], 2>
    for SimpleHybridCompressor<C1, C2, W1, W2, DIGEST_ELEMS_1, DIGEST_ELEMS_2, NC>
where
    C1: PseudoCompressionFunction<[W1; DIGEST_ELEMS_1], 2> + Clone,
    C2: PseudoCompressionFunction<[W2; DIGEST_ELEMS_2], 2> + Clone,
    W1: Clone,
    W2: Clone,
    NC: NodeConverter<[W1; DIGEST_ELEMS_1], [W2; DIGEST_ELEMS_2]> + Clone,
{
    fn compress(
        &self,
        input: [[W1; DIGEST_ELEMS_1]; 2],
        sizes: &[usize],
        current_size: usize,
    ) -> [W1; DIGEST_ELEMS_1] {
        if current_size == sizes[0] {
            self.c1.compress(input)
        } else {
            let [input_0, input_1] = input;
            let input_w2 = [NC::to_n2(input_0), NC::to_n2(input_1)];
            NC::to_n1(self.c2.compress(input_w2))
        }
    }
}