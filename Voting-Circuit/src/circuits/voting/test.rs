#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_ec::AffineRepr;
    use ark_ff::Field;
    use crate::circuits::voting::{voting_circuit::VotingCircuit, MockingCircuit};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_groth16::Groth16;
    use ark_crypto_primitives::snark::SNARK;
    use crate::circuits::voting::parser::{get_ck, get_g, get_user, parse_user};
    use crate::circuits::voting::{
        setup::voting_setup,
        prover::voting_prove
    };
    
    type C = ark_ed_on_bn254::EdwardsProjective;
    type GG = ark_ed_on_bn254::constraints::EdwardsVar;

    type F = ark_bn254::Fr;


    fn make_mocking_circuit() -> VotingCircuit<C, GG> {
        let tree_height = 10;       // constant
        let voting_round = 1;       // mutable
        let num_of_candidates = 2; // mutable
        let num_of_voters = 2;     // mutable
        let vote_index = 1;         // mutable  (num_of_candidates보다 작아야함)
        let voter_pos = 1;          // mutable (Mock data에 addr이 0 ~ 9)까지 준비되어있음. num_of_voters보다 작아야함
        let candidate_limit = 2;   // constant
        
        
        let g = get_g().unwrap();
        let ck = get_ck().unwrap();
        let user = get_user(voter_pos.clone() as usize).unwrap();
        let parsed_user = parse_user(&user).unwrap();
        let sk = parsed_user.sk;
        let pk = parsed_user.pk;

        let test_circuit = <VotingCircuit<C, GG> as MockingCircuit<C, GG>>::generate_circuit(
            g, ck, sk, pk, tree_height, voting_round, num_of_candidates, num_of_voters, vote_index, voter_pos, candidate_limit
        ).unwrap();

        test_circuit
    }

    #[test]
    fn test_voting_constraints() {
        use ark_relations::r1cs::ConstraintSynthesizer;
        let test_circuit = make_mocking_circuit();
        let cs = ConstraintSystem::<F>::new_ref();

        test_circuit.clone().generate_constraints(cs.clone()).unwrap();
        println!("Number of constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }


    #[test]
    fn test_voting_setup() {
        let test_circuit = make_mocking_circuit();
        voting_setup(test_circuit);
    }

    #[test]
    fn test_voting_prove() {
        use crate::circuits::voting::key_utils::{load_pk, load_vk};
        let test_circuit = make_mocking_circuit();
        println!("loading ...");
        let pk = load_pk();
        let vk = load_vk();
        println!("loaded !");
        println!("vk.alpha_g1: {:?}\n", vk.alpha_g1);
        println!("vk.beta_g2: {:?}\n", vk.beta_g2);
        println!("vk.gamma_g2: {:?}\n", vk.gamma_g2);
        println!("vk.delta_g2: {:?}\n", vk.delta_g2);
        println!("vk.gamma_abc_g1: {:?}\n", vk.gamma_abc_g1);
        println!("len(vk.gamma_abc_g1): {:?}\n", vk.gamma_abc_g1.len());
    
        let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();
        let mut image: Vec<_> = vec![];

        image.append(&mut vec![
            test_circuit.instance.voting_round.clone().unwrap(),
            test_circuit.instance.root.clone().unwrap(),
        ]);

        for i in test_circuit.instance.vote_cm.clone().unwrap() {
            if i.is_zero() {
                let zero = F::ZERO;
                image.push(zero); // TODO: num_of_candidate가 candidate_limit보다 작을 경우, 에러가 발생함.
                image.push(zero);
            }
            else {
                image.push(*i.clone().x().unwrap());
                image.push(*i.clone().y().unwrap());
            }
        }

        println!("image: {:?}", image);
        
        let mut image_for_sc = vec![];
        for i in image.clone().iter() {
            image_for_sc.push(i.to_string());
        }

        println!("image_for_sc: {:?}", image_for_sc);
        println!("len(image_for_sc): {:?}", image_for_sc.len());
        
        let proof = voting_prove(pk, test_circuit);
        println!("proof: {:?}", proof);
        assert!(Groth16::<Bn254>::verify_with_processed_vk(&pvk, &image, &proof).unwrap());
    }   
}





// 0번에게 투표
// [
//     [
//         [
//             11033567818275684919075409414965572079440635723229613164682361884895658975772, 481411362403504201447508112774593803602760479581675224881324297265530828000
//         ], 
//         [
//             16955724471882459149810129443345563406537256917349110988888829087554591653765, 14200917651984717562329172401068559260002533199645482705628663576896616142061
//         ]
//     ],
//     [
//         [
//             11212910480919613759821103829670285558249846784935520403521985325130665370736, 3009261360349294882390304634382566512115473377405587968582582965939927593015
//         ],
//         [
//             9405646435127829239500635852624372803665573127309098866323303401372794688110, 11807384405777212140361874267048608283976813534510199002672246914609996440751
//         ]
//     ]
// ]