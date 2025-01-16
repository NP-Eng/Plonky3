use alloc::vec::Vec;

use p3_dft::{NaiveDft, TwoAdicSubgroupDft};
use p3_field::TwoAdicField;
use p3_interpolation::interpolate_coset;
use p3_matrix::Matrix;

use crate::polynomial::Polynomial;

#[cfg(test)]
mod tests;

/// Coset of a smooth subgroup of the group of units of a finite field (smooth
/// meaning: having power-of-2 order).
#[derive(Clone, Debug)]
pub struct Radix2Coset<F: TwoAdicField> {
    root_of_unity: F,
    generator: F,
    generator_inv: F,
    shift: F,
    log_size: usize,
}

impl<F: TwoAdicField> Radix2Coset<F> {
    pub fn new(shift: F, log_size: usize) -> Self {
        let generator = F::two_adic_generator(log_size);
        Self {
            root_of_unity: generator.clone(),
            generator,
            generator_inv: generator.inverse(),
            shift,
            log_size,
        }
    }

    pub fn new_from_degree_and_rate(log_degree: usize, log_rate: usize) -> Self {
        let log_size = log_degree + log_rate;
        let generator = F::two_adic_generator(log_size);
        Self {
            root_of_unity: generator.clone(),
            generator,
            generator_inv: generator.inverse(),
            shift: F::ONE,
            log_size,
        }
    }

    pub fn log_size(&self) -> usize {
        self.log_size
    }

    /// Reduce the size of the subgroup by a factor of 2^log_scale_factor
    /// this leaves the shift untouched
    pub fn shrink_subgroup(&self, log_scale_factor: usize) -> Radix2Coset<F> {
        let generator = self.generator.exp_power_of_2(log_scale_factor);
        Radix2Coset {
            generator,
            generator_inv: generator.inverse(),
            log_size: self.log_size - log_scale_factor,
            shift: self.shift,
            root_of_unity: self.root_of_unity,
        }
    }

    /// Reduce the size of the coset by a factor of 2^log_scale_factor
    /// the shift is raised to the power of 2^log_scale_factor
    // NP TODO shrink_and_shift
    pub fn shrink_coset(&self, log_scale_factor: usize) -> Radix2Coset<F> {
        let generator = self.generator.exp_power_of_2(log_scale_factor);
        let shift = self.shift.exp_power_of_2(log_scale_factor);
        Radix2Coset {
            root_of_unity: self.root_of_unity,
            generator,
            generator_inv: generator.inverse(),
            shift,
            log_size: self.log_size - log_scale_factor,
        }
    }

    /// Shift the coset by an element of the field
    pub fn shift_by(&self, shift: F) -> Radix2Coset<F> {
        let mut shifted = self.clone();
        shifted.shift = self.shift * shift;
        shifted
    }

    pub fn shift_by_root_of_unity(&self) -> Radix2Coset<F> {
        let mut shifted = self.clone();
        shifted.shift = self.shift * self.root_of_unity;
        shifted
    }

    /// Set the shift of the coset to a given element
    pub fn set_shift(&self, shift: F) -> Radix2Coset<F> {
        let mut shifted = self.clone();
        shifted.shift = shift;
        shifted
    }

    /// Checks if a given element is in the coset
    pub fn contains(&self, element: F) -> bool {
        // Note that a subgroup of order n of the group of units of a field is
        // necessarily the group of n-th roots of unity. Therefore, testing for
        // belonging to that group can be done by raising to its order.
        element.exp_power_of_2(self.log_size) == F::ONE
    }

    pub fn evaluate_interpolation<Mat>(&self, coset_evals: &Mat, point: F) -> Vec<F>
    where
        Mat: Matrix<F>,
    {
        // NP TODO: Make use of the denominator diffs for efficiency
        interpolate_coset(coset_evals, self.shift, point, None)
    }

    // NP interpolate(
    pub fn interpolate_evals(&self, evals: Vec<F>) -> Polynomial<F> {
        let mut evals = evals;
        evals.resize(1 << self.log_size, F::ZERO);
        // NP TODO is there a better impl?
        let dft = NaiveDft.coset_idft(evals, self.shift);
        Polynomial::from_coeffs(dft)
    }

    /// NP TODO: No optimization here
    pub fn element(&self, index: u64) -> F {
        self.shift * self.generator.exp_u64(index)
    }

    pub fn evaluate_polynomial(&self, polynomial: &Polynomial<F>) -> Vec<F> {
        let mut coeffs = polynomial.coeffs().to_vec();
        coeffs.resize(1 << self.log_size, F::ZERO);
        let dft = NaiveDft.coset_dft(coeffs, self.shift);
        dft
    }
}

impl<F: TwoAdicField> PartialEq for Radix2Coset<F> {
    fn eq(&self, other: &Self) -> bool {
        self.generator == other.generator && other.contains(self.shift)
    }
}

impl<F: TwoAdicField> Eq for Radix2Coset<F> {}
