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
        let vote_index = 0;         // mutable  (num_of_candidates보다 작아야함)
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
//             20829713434596791778325357485089886747514778316705676669650462347841700928402, 16211914032676110342504483473133854906048312474481567465777862980221140582806
//         ], 
//         [
//             21751743789253487890573857635505293176330901016696147827392093312092203356275, 21649100111684828425067547456894035102243944074454781695410098950567605692917
//         ]
//     ],
//     [
//         [
//             11423542327632730572517626166992096298549771866687099793864554437116717745098, 11855164744168886613412067862405605895865801597166913884599362920502551505223
//         ],
//         [
//             3430020931225080008428116447967980394610517623332496955004514443233458783286, 16576259033801907607559578885637300221814760878233642826153650819230502050183
//         ]
//     ]
// ]