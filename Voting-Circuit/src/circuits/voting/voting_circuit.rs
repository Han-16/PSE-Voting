use std::marker::PhantomData;
use ark_ec::CurveGroup;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{prelude::*, fields::fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_crypto_primitives::{
    crh::{poseidon::constraints::{CRHGadget, CRHParametersVar}, CRHSchemeGadget}, 
    sponge::{poseidon::PoseidonConfig, Absorb},
    merkle_tree::{self, constraints::PathVar},
};

use crate::circuits::voting::merkle_tree::{MerkleTreeParams, MerkleTreeParamsVar};

pub type ConstraintF<C> = <<C as CurveGroup>::BaseField as Field>::BasePrimeField;

#[derive(Clone, Debug)]
pub struct VotingInstance<C: CurveGroup> {
    pub voting_round: Option<C::BaseField>,
    pub root: Option<C::BaseField>,
    pub vote_cm: Option<Vec<C::Affine>>,
}

#[derive(Clone, Debug)]
pub struct VotingWitness<C: CurveGroup>
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
pub struct VotingCircuit<C: CurveGroup, GG: CurveVar<C, ConstraintF<C>>>
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

impl<C, GG> ConstraintSynthesizer<C::BaseField> for VotingCircuit<C, GG>
where 
    C: CurveGroup,
    GG: CurveVar<C, C::BaseField>,
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<C::BaseField>) -> ark_relations::r1cs::Result<()> {
        let g = GG::new_constant(cs.clone(), self.g)?;
        let ck = Vec::<GG>::new_constant(cs.clone(), self.ck)?;
        let hash_params = CRHParametersVar::<C::BaseField>::new_constant(cs.clone(), self.hash_params)?;
        let zero = FpVar::<C::BaseField>::zero();
        let one = FpVar::<C::BaseField>::one();

        // instance
        let voting_round = FpVar::<C::BaseField>::new_input(cs.clone(), || self.instance.voting_round.ok_or(SynthesisError::AssignmentMissing))?;
        let root = FpVar::<C::BaseField>::new_input(cs.clone(), || self.instance.root.ok_or(SynthesisError::AssignmentMissing))?;
        let vote_cm = Vec::<GG>::new_input(cs.clone(), || self.instance.vote_cm.ok_or(SynthesisError::AssignmentMissing))?;


        // witness
        let sk = FpVar::<C::BaseField>::new_witness(cs.clone(), || self.witness.sk.ok_or(SynthesisError::AssignmentMissing))?;
        let pk = GG::new_witness(cs.clone(), || self.witness.pk.ok_or(SynthesisError::AssignmentMissing))?;
        let addr = FpVar::<C::BaseField>::new_witness(cs.clone(), || self.witness.addr.ok_or(SynthesisError::AssignmentMissing))?;
        let vote_m = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || self.witness.vote_m.ok_or(SynthesisError::AssignmentMissing))?;
        let vote_r = Vec::<FpVar<C::BaseField>>::new_witness(cs.clone(), || self.witness.vote_r.ok_or(SynthesisError::AssignmentMissing))?;
        let sn = FpVar::<C::BaseField>::new_witness(cs.clone(), || self.witness.sn.ok_or(SynthesisError::AssignmentMissing))?;
        let leaf_pos = UInt32::new_witness(cs.clone(), || self.witness.leaf_pos.ok_or(SynthesisError::AssignmentMissing))?.to_bits_le();
        let mut cw = PathVar::<
                MerkleTreeParams<C::BaseField>,
                C::BaseField,
                MerkleTreeParamsVar<C::BaseField>,
            >::new_witness(cs.clone(), || self.witness.tree_proof.ok_or(SynthesisError::AssignmentMissing))?;


        // Constraints

        // 1. Check pk = g^sk
        let sk_bits = sk.to_bits_le()?;
        let pk_computed = g.scalar_mul_le(sk_bits.iter())?;
        pk_computed.enforce_equal(&pk)?;


        // 2. Check addr = CRH(pk)
        let pk_bits = pk.clone().to_bits_le()?;
        let pk_x = Boolean::le_bits_to_fp_var(&pk_bits[..pk_bits.len() / 2])?;
        let pk_y = Boolean::le_bits_to_fp_var(&pk_bits[pk_bits.len() / 2..])?;

        let hash_input = vec![pk_x, pk_y];
        let addr_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input)?;
        addr_computed.enforce_equal(&addr)?;


        // 3. Check sn = CRH(voting_round || sk)
        let hash_input = vec![voting_round, sk];
        let sn_computed = CRHGadget::<C::BaseField>::evaluate(&hash_params, &hash_input)?;
        sn_computed.enforce_equal(&sn)?;

        
        // 4. Check vote_cm = g^mh^r
        for (i, (vote_m_i, vote_r_i)) in vote_m.iter().zip(vote_r.iter()).enumerate() {
            let vote_cm_computed = ck[0].scalar_mul_le(vote_m_i.to_bits_le()?.iter())? + ck[1].scalar_mul_le(vote_r_i.to_bits_le()?.iter())?;
            vote_cm[i].enforce_equal(&vote_cm_computed)?;
        }


        // 5. Sum(vote_m) == 1
        let sum_vote_m = vote_m.iter().fold(FpVar::zero(), |acc, vote| acc + vote);
        sum_vote_m.enforce_equal(&one)?;

        
        // 6. vote_m[i] == 0 or 1
        for i in vote_m.iter() {
            let vote_m_i_sq = i * i;
            let vote_m_sq_minus_vote_m = vote_m_i_sq - i;
            vote_m_sq_minus_vote_m.enforce_equal(&zero)?;
        }
        

        // 7. MT.verify(addr, path, root) = true
        let leaf_g = vec![addr.clone()];
        cw.set_leaf_position(leaf_pos.clone());
        let path_check = cw.verify_membership(&hash_params, &hash_params, &root, &leaf_g)?;
        path_check.enforce_equal(&Boolean::Constant(true))?;
        Ok(())
    }
}