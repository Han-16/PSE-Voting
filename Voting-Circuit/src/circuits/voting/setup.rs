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


#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bn254::{EdwardsProjective as C, constraints::EdwardsVar as GG};
    use crate::circuits::voting::MockingCircuit;
    use crate::circuits::voting::parser::*;
    use std::path::Path;

    fn make_mocking_circuit() -> VotingCircuit<C, GG> {
        let tree_height = 4;
        let voting_round = 1;
        let num_of_candidates = 2;
        let num_of_voters = 12;
        let vote_index = 1;
        let voter_pos = 10;
        let candidate_limit = 10;
        
        
        let g = get_g().unwrap();
        let ck = get_ck().unwrap();
        let user = get_user(0).unwrap();
        let parsed_user = parse_user(&user).unwrap();
        let sk = parsed_user.sk;
        let pk = parsed_user.pk;

        let test_circuit = <VotingCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            g, ck, sk, pk, tree_height, voting_round, num_of_candidates, num_of_voters, vote_index, voter_pos, candidate_limit
        ).unwrap();

        test_circuit
    }

    #[test]
    fn test_voting_setup() {
        let test_circuit = make_mocking_circuit();
        let (pk, vk, pvk) = voting_setup(test_circuit);
        println!("vk.alpha_g1: {:?}", vk.alpha_g1);
        println!("vk.beta_g2: {:?}", vk.beta_g2);
        println!("vk.gamma_g2: {:?}", vk.gamma_g2);
        println!("vk.delta_g2: {:?}", vk.delta_g2);
        println!("vk.gamma_abc_g1: {:?}", vk.gamma_abc_g1);
    }

    #[test]
    fn test_load_pk_vk() {
        let test_circuit = make_mocking_circuit();
        let (pk, vk, _) = voting_setup(test_circuit);

        assert!(Path::new("./src/keys/voting/voting.pk.dat").exists());
        assert!(Path::new("./src/keys/voting/voting.vk.dat").exists());

        let loaded_pk = load_pk();
        let loaded_vk = load_vk();

        assert_eq!(pk, loaded_pk);
        assert_eq!(vk, loaded_vk);
    }
}