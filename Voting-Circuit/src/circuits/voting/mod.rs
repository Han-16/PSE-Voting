pub mod voting_circuit;
pub mod merkle_tree;

use ark_crypto_primitives::sponge::Absorb;
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_r1cs_std::groups::{CurveVar, GroupOpsBounds};

use crate::Error;

pub trait MockingCircuit<C, GG>
where
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F;
    type HashParam;
    type H;
    type Output;

    fn generate_circuit<R: ark_std::rand::Rng>(
        hash_param: Self::HashParam,
        tree_height: u64,
        voting_round: u64,
        rng: &mut R,
    ) -> Result<Self::Output, Error>;
}
