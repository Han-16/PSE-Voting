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

impl<C, GG> VotingCircuit<C, GG>
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


        // 3. Check sn = CRH(sk || voting_round)
        let hash_input = vec![sk, voting_round];
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


impl<C: CurveGroup, GG: CurveVar<C, C::BaseField>> MockingCircuit<C, GG> for VotingCircuit<C, GG>
where 
    <C as CurveGroup>::BaseField: PrimeField + Absorb,
    for<'a> &'a GG: GroupOpsBounds<'a, C, GG>,
{
    type F = C::BaseField;
    type HashParam = PoseidonConfig<Self::F>;
    type H = CRH<Self::F>;
    type Output = VotingCircuit<C, GG>;

    fn generate_circuit(
            g: C::Affine,
            ck: Vec<C::Affine>,
            sk: C::BaseField,
            pk: C::Affine,
            tree_height: u64,
            voting_round: u64,
            num_of_candidates: u64,
            num_of_voters: u64,
            vote_index: u64,  // index of the candidate that the voter is voting for
            voter_pos: u64,  // index of the voter
            candidate_limit: u64,
        ) -> Result<Self::Output, crate::Error> {
        use ark_ec::AffineRepr;
        use ark_std::{UniformRand, One};
        use ark_std::rand::RngCore;
        use ark_std::rand::SeedableRng;
        use ark_std::test_rng;
        use std::str::FromStr;
        use num_bigint::BigUint;
        use crate::circuits::voting::parser::*;

        // let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
        let mut rng = thread_rng();
        println!("ck: {:?}", ck.iter().map(|x| x.to_string()).collect::<Vec<String>>());

        // Generate the hash parameters
        let hash_params: PoseidonConfig<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> = get_poseidon_params();

        // addr = CRH(pk)
        let (pk_x, pk_y) = pk.xy().unwrap();
        let addr = Self::H::evaluate(&hash_params, vec![pk_x.clone(), pk_y.clone()]).unwrap();

        // voting round
        let voting_round = Self::F::from(voting_round);

        // sn
        let sn = Self::H::evaluate(&hash_params, vec![sk, voting_round]).unwrap();
        println!("sn: {:?}", sn.to_string());

        // vote_m
        let mut vote_m = vec![Self::F::zero(); candidate_limit as usize];
        if (vote_index as usize) < candidate_limit as usize {
            vote_m[vote_index as usize] = Self::F::one();
        }

        let vote_m_str = vote_m.iter().map(|x| x.to_string()).collect::<Vec<String>>();
        println!("vote_m: {:?}", vote_m_str);

        // vote_r
        let mut vote_r = vec![];
        for i in 0..candidate_limit {
            if i < num_of_candidates {
                let random = Self::F::rand(&mut rng);
                vote_r.push(random);
            } else {
                vote_r.push(Self::F::zero());
            }
        }

        // g^r
        let mut g_r = vec![];
        for i in 0..candidate_limit as usize {
            let g_r_i = g.mul_bigint(&vote_r[i].into_bigint());
            g_r.push(g_r_i.into_affine());
        }

        let g_r_str = g_r.iter().map(|x| x.to_string()).collect::<Vec<String>>();

        // vote_cm (g^mh^r)
        let mut vote_cm = vec![];
        for i in 0..candidate_limit as usize {
            let vote_cm_i = ck[0].mul_bigint(&vote_m[i].into_bigint()) + ck[1].mul_bigint(&vote_r[i].into_bigint());
            vote_cm.push(vote_cm_i.into_affine());
        }

        let vote_cm_str = vote_cm.iter().map(|x| x.to_string()).collect::<Vec<String>>();
        
        // print g^r_i, vote_cm_i
        for i in 0..candidate_limit as usize {
            println!("g^r_{}: {:?}", i, g_r_str[i]);
            println!("g^mh^r_{}: {:?}\n", i, vote_cm_str[i]);
        }


        // Merkle tree
        let leaf_crh_params = hash_params.clone();
        let two_to_one_params = hash_params.clone();

        let num_leaves = 2_usize.pow(tree_height as u32);
        let mut leaves = vec![];

        for i in 0..num_of_voters as usize {
            let user_addr_str: String = get_user(i).unwrap().addr;
            let user_addr_bigint = BigUint::from_str(&user_addr_str).unwrap();
            let user_addr_bytes = user_addr_bigint.to_bytes_le();
            let user_addr = Self::F::from_le_bytes_mod_order(&user_addr_bytes);
            leaves.push([user_addr]);
        }
    
        while leaves.len() < num_leaves {
            leaves.push([Self::F::zero()]);
        }

        let tree = MerkleTree::<MerkleTreeParams<Self::F>>::new(
            &leaf_crh_params,
            &two_to_one_params,
            leaves,
        )?;
        
        let root = tree.root().clone();
        println!("Root: {:?}", root.to_string());
        let merkle_proof = tree.generate_proof(voter_pos as usize)?;

        let instance = VotingInstance {
            voting_round: Some(voting_round),
            root: Some(root),
            vote_cm: Some(vote_cm),
        };

        let witness = VotingWitness {
            sk: Some(sk),
            pk: Some(pk),
            addr: Some(addr),
            vote_m: Some(vote_m),
            vote_r: Some(vote_r),
            sn: Some(sn),
            leaf_pos: Some(voter_pos as u32),
            tree_proof: Some(merkle_proof),
        };

        Ok(Self::new(g, ck, hash_params, instance, witness))
    }
}



