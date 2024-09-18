pub mod voting_circuit;
pub mod merkle_tree;
pub mod test;
pub mod poseidon_params;
pub mod parser;
pub mod prover;
pub mod setup;
pub mod key_utils;

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

    fn generate_circuit(
        g: C::Affine,
        ck: Vec::<C::Affine>,
        sk: C::BaseField,
        pk: C::Affine,
        tree_height: u64,
        voting_round: u64,
        num_of_candidates: u64,
        num_of_voters: u64,
        vote_index: u64,
        voter_pos: u64,
        candidate_limit: u64,
    ) -> Result<Self::Output, Error>;
}
