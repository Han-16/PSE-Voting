#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use crate::circuits::voting::{voting_circuit::VotingCircuit, MockingCircuit};
    use ark_relations::r1cs::ConstraintSystem;
    use ark_groth16::Groth16;
    use ark_crypto_primitives::snark::SNARK;
    use ark_r1cs_std::groups::curves::short_weierstrass::AffineVar;
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
        let num_of_candidates = 3; // mutable
        let num_of_voters = 3;     // mutable
        let vote_index = 1;         // mutable  (num_of_candidates보다 작아야함)
        let voter_pos = 2;          // mutable (Mock data에 addr이 0 ~ 9)까지 준비되어있음. num_of_voters보다 작아야함
        let candidate_limit = 3;   // constant
        
        
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
    fn pick_bn128_point() {
        use ark_std::test_rng;
        use ark_bn254::G1Affine;
        use ark_ff::UniformRand;
        let mut rng = test_rng();

        let p1 = G1Affine::rand(&mut rng);
        let p2 = G1Affine::rand(&mut rng);
        
        let result = (p1 + p2).into_affine();
    
        println!("p1: {:?}", p1);
        println!("p2: {:?}", p2);
        println!("result: {:?}", result);
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
//             7002423165718862390085497292383722681186819064610927722206147313123556968176, 1158418138796569270227409703907560298194780201830254536705718434563959474250
//         ], 
//         [
//             1648432218916581718736433422721440114484717793513633214439675109043745167507, 16252806229216206557842960347496532192895446003208121887189965450592401622307
//         ]
//     ],
//     [
//         [
//             8162470543121127218496399265061141533628918683931781537562787518760810080332, 17574063265327651113532670727085148159901031970287820058245132483187161566352
//         ],
//         [
//             21331332089127842605625988752397999957332325790147087438304646118286698234766, 18781616259708682926544928743402266418164030872090275689986131720542588831362
//         ]
//     ]
// ]