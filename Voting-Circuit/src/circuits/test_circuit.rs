use std::marker::PhantomData;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{prelude::*, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_crypto_primitives::{
    crh::{poseidon::{constraints::{CRHGadget, CRHParametersVar}, CRH}, CRHScheme, CRHSchemeGadget}, encryption::elgamal::constraints::ConstraintF, merkle_tree::{self, constraints::PathVar, MerkleTree}, sponge::{poseidon::PoseidonConfig, Absorb}
};
use ark_std::Zero;
use rand::thread_rng;

#[derive(Clone, Debug)]
pub struct TestInstance<C: CurveGroup> {
    pub p1: Option<C::Affine>,
    pub p2: Option<C::Affine>,
}

#[derive(Clone, Debug)]
pub struct TestWitness<C: CurveGroup> {
    pub m: Option<C::BaseField>,
}

#[derive(Clone, Debug)]
pub struct TestCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>> {
    pub instance: TestInstance<C>,
    pub witness: TestWitness<C>,
    _curve: PhantomData<GG>,
}

impl<C, GG> ConstraintSynthesizer<C::BaseField> for TestCircuit<C, GG>
where 
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<C::BaseField>) -> ark_relations::r1cs::Result<()> {
        let p1 = GG::new_input(cs.clone(), || self.instance.p1.ok_or(SynthesisError::AssignmentMissing))?;
        let p2 = GG::new_input(cs.clone(), || self.instance.p2.ok_or(SynthesisError::AssignmentMissing))?;
        let m = FpVar::<C::BaseField>::new_witness(cs.clone(), || self.witness.m.ok_or(SynthesisError::AssignmentMissing))?;

        let m_bits = m.to_bits_le()?;
        let computed_p2 = p1.scalar_mul_le(m_bits.iter())?;
        p2.enforce_equal(&computed_p2)?;
        Ok(())
    }
}





#[cfg(test)]
pub mod bn254_test {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_ff::Field;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_crypto_primitives::snark::SNARK;
    use ark_groth16::Groth16;
    type C = ark_bn254::G1Projective;
}