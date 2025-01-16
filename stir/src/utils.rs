use core::iter;

use itertools::Itertools;
use p3_field::TwoAdicField;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;

use crate::polynomial::Polynomial;

pub(crate) fn compute_pow(security_level: usize, error: f64) -> f64 {
    0f64.max(security_level as f64 - error)
}

pub(crate) fn fold_polynomial<F: TwoAdicField>(
    polynomial: &Polynomial<F>,
    folding_randomness: F,
    log_folding_factor: usize,
) -> Polynomial<F> {
    let folding_factor = 1 << log_folding_factor;
    let fold_size = (polynomial.degree() + 1).div_ceil(folding_factor);

    let folding_powers = iter::successors(Some(F::one()), |&x| Some(x * folding_randomness))
        .take(folding_factor)
        .collect_vec();

    let mut folded_coeffs = vec![F::zero(); fold_size];

    // NP TODO remove or move:
    // Example:
    // 1 + 2*x + 3*x^2 + 4*x^3 + 5*x^4 + 6*x^5 + 7*x^6 + 8*x^7
    // folding_factor = 4
    // fold_size = 2
    // folding_powers = [1, r, r^2, r^3]
    // folded_polynomial = (1 + 5x) + r * (2 + 6x) + r^2 * (3 + 7x) + r^3 * (4 + 8x)
    //                   = (1 + 2r + 3r^2 + 4r^3) + (5 + 6r + 7r^2 + 8r^3)x

    for (i, coeff) in polynomial.coeffs().iter().enumerate() {
        folded_coeffs[i / folding_factor] += *coeff * folding_powers[i % folding_factor];
    }

    Polynomial::from_coeffs(folded_coeffs)
}

#[cfg(test)]
mod tests {
    use core::assert_eq;

    use iter::Iterator;
    use p3_baby_bear::BabyBear;
    use p3_field::AbstractField;
    use rand::Rng;

    use super::*;
    use crate::polynomial::rand_poly;

    type F = BabyBear;

    #[test]
    fn test_fold_polynomial() {
        let polynomial = Polynomial::<F>::from_coeffs(vec![F::one(); 16]);
        let folding_randomness = F::from_canonical_u32(3);

        // log_folding_factor = 1
        assert_eq!(
            fold_polynomial(&polynomial, folding_randomness, 1).coeffs(),
            vec![4, 4, 4, 4, 4, 4, 4, 4]
                .into_iter()
                .map(F::from_canonical_u32)
                .collect_vec()
        );

        // log_folding_factor = 2
        assert_eq!(
            fold_polynomial(&polynomial, folding_randomness, 2).coeffs(),
            vec![40, 40, 40, 40]
                .into_iter()
                .map(F::from_canonical_u32)
                .collect_vec()
        );
    }

    #[test]
    fn test_fold_backwards() {
        let fold_degree = 5;
        let log_folding_factor = 4;

        let folding_factor = 1 << log_folding_factor;

        let mut rng = rand::thread_rng();

        let folding_randomness: F = rng.gen();

        let folds = (0..folding_factor)
            .map(|_| rand_poly::<F>(fold_degree))
            .collect_vec();

        let powers_of_x = iter::successors(Some(Polynomial::one()), |p| {
            Some(&Polynomial::monomial(F::zero()) * p)
        })
        .take(folding_factor)
        .collect_vec();

        let polynomial = folds
            .iter()
            .map(|fold| fold.compose_with_exponent(folding_factor))
            .zip(powers_of_x.iter())
            .fold(Polynomial::zero(), |acc, (raised_fold, power_of_x)| {
                // NP TODO maybe method multiply_by_xn(exp)? or have * detect
                // which situation it is
                &acc + &(&raised_fold * power_of_x)
            });

        let powers_of_r = iter::successors(Some(F::one()), |&x| Some(x * folding_randomness))
            .take(folding_factor)
            .collect_vec();

        let expected_folded_polynomial = folds
            .iter()
            .zip(powers_of_r.iter())
            .map(|(p, r)| p * r)
            .fold(Polynomial::zero(), |acc, p| &acc + &p);

        assert_eq!(
            fold_polynomial(&polynomial, folding_randomness, log_folding_factor),
            expected_folded_polynomial
        );
    }
}
