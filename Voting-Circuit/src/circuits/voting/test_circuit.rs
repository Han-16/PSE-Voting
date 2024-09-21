use std::marker::PhantomData;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{prelude::*, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_crypto_primitives::{
    crh::{poseidon::{constraints::{CRHGadget, CRHParametersVar}, CRH}, CRHScheme, CRHSchemeGadget}, merkle_tree::{self, constraints::PathVar, MerkleTree}, sponge::{poseidon::PoseidonConfig, Absorb}
};
use ark_std::Zero;
use rand::thread_rng;
use crate::circuits::voting::merkle_tree::{MerkleTreeParams, MerkleTreeParamsVar};
use crate::circuits::voting::MockingCircuit;
use crate::circuits::voting::poseidon_params::get_poseidon_params;

#[derive(Clone, Debug)]
pub struct TestInstance<C: CurveGroup> {
    pub voting_round: Option<C::BaseField>,
    pub root: Option<C::BaseField>,
    pub vote_cm: Option<Vec<C::Affine>>,
}

#[derive(Clone, Debug)]
pub struct TestWitness<C: CurveGroup> 
where 
    C::BaseField: PrimeField + Absorb,
{
    pub sk: Option<C::BaseField>,
    pub pk: Option<C::Affine>,
    pub addr: Option<C::BaseField>,
    pub vote_m: Option<Vec<C::BaseField>>,
    pub vote_r: Option<Vec<C::BaseField>>,
    pub sn: Option<C::BaseField>,
    pub leaf_pos: Option<u32>,
    pub tree_proof: Option<merkle_tree::Path<MerkleTreeParams<C::BaseField>>>,
}

#[derive(Clone, Debug)]
pub struct TestCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
where 
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub g: C::Affine,
    pub ck: Vec<C::Affine>,
    pub hash_params: PoseidonConfig<C::BaseField>,
    pub instance: VotingInstance<C>,
    pub witness: VotingWitness<C>,
    _curve: PhantomData<GG>,
}

impl<C, GG> TestCircuit<C, GG>
where 
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    pub fn new(
        g: C::Affine,
        ck: Vec<C::Affine>,
        hash_params: PoseidonConfig<C::BaseField>,
        instance: VotingInstance<C>,
        witness: VotingWitness<C>,
    ) -> Self {
        Self {
            g,
            ck,
            hash_params,
            instance,
            witness,
            _curve: PhantomData,
        }
    }
}

