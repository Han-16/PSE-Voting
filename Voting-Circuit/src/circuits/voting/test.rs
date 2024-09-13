#[cfg(test)]
mod test {
    use crate::circuits::voting::{voting_circuit::VotingCircuit, MockingCircuit};
    use ark_crypto_primitives::{
        crh::{poseidon::{TwoToOneCRH, CRH}, CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{self, constraints::PathVar, MerkleTree},
        sponge::{poseidon::PoseidonConfig, Absorb}
    };
    use ark_ec::{CurveGroup, AffineRepr};
    use ark_relations::r1cs::ConstraintSystem;
    use std::str::FromStr;
    use crate::circuits::voting::parser::{User, ParsedUser,get_users, get_ck, get_g, get_user, parse_user};
    
    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;

    type F = ark_bn254::Fr;

    #[test]
    fn test_poseidon_hash() {
        use crate::circuits::voting::poseidon_params::get_poseidon_params;

        let hash_params: PoseidonConfig<<<C as CurveGroup>::Affine as AffineRepr>::BaseField> = get_poseidon_params();

        
        let left_1 = F::from_str("5606718420606443971671484895049764524137380043712288683633077955014799326746").unwrap();
        let right_1 = F::from_str("17197717161227025415653362559402002071764119382426881957576028977161869254459").unwrap();
        
        let left_2 = F::from_str("1183541264794662596260109398285142046445627481274933684025919000314869820549").unwrap();
        let right_2 = F::from_str("2798884284280419056895756479481872730400655255609110844083423702997077305745").unwrap();
        
        let result_1_eval = CRH::<F>::evaluate(&hash_params, vec![left_1, right_1]).unwrap();
        let result_2_eval = CRH::<F>::evaluate(&hash_params, vec![left_2, right_2]).unwrap();
        let result_1_comp = TwoToOneCRH::<F>::compress(&hash_params, left_1, right_1).unwrap();
        let result_2_comp = TwoToOneCRH::<F>::compress(&hash_params, left_2, right_2).unwrap();
        
        let expected_root = F::from_str("7589531496280468984030793369747668473312938794789330702447487778151327843690").unwrap();
        let root_eval = CRH::<F>::evaluate(&hash_params, vec![result_1_eval, result_2_eval]).unwrap();
        let root_comp = TwoToOneCRH::<F>::compress(&hash_params, result_1_comp, result_2_comp).unwrap();

        assert_eq!(root_eval, expected_root);
        assert_eq!(root_comp, expected_root);
    }

    #[test]
    fn test_voting_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;
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

        let cs = ConstraintSystem::<F>::new_ref();

        test_circuit.clone().generate_constraints(cs.clone()).unwrap();
        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }
}