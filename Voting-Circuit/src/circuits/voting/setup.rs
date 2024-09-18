use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_std::rand::thread_rng;
use ark_crypto_primitives::snark::SNARK;
use crate::circuits::voting::key_utils::*;

use super::voting_circuit::VotingCircuit;

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;



pub fn voting_setup(circuit: VotingCircuit<C, GG>) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>, PreparedVerifyingKey<Bn254>) {
    let rng = &mut thread_rng();

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();

    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    store_pk_vk(pk.clone(), vk.clone());

    (pk, vk, pvk)
}