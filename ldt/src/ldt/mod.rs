// NP TODO documentation

// TODO add examples that shows

use p3_commit::Mmcs;
use p3_field::Field;

/// Low-degree testing using MMCS
trait Ldt<F, M>
where
    F: Field,
    M: Mmcs<F>,
{
    /// The configuration of the LDT.
    type Config;
    /// The proof of low-degreeness.
    type Proof;
    /// Data to M::ProverData that the prover needs when proving low-degreeness
    type ProverData;
    /// The error type for the verifier.
    type VerificationError;

    // NP TODO do we need self?
    fn commit(&self, config: &Self::Config) -> (Self::ProverData, M::Commitment);
    fn prove(
        &self,
        config: &Self::Config,
        prover_data: Self::ProverData,
        commitment: &M::Commitment,
    ) -> Self::Proof;
    fn verify(
        &self,
        config: &Self::Config,
        commitment: &M::Commitment,
        proof: &Self::Proof,
    ) -> Result<(), Self::VerificationError>;
}
