use ark_bn254::Bn254;
use ark_groth16::{Groth16, PreparedVerifyingKey, ProvingKey, VerifyingKey};
use ark_std::rand::thread_rng;
use ark_crypto_primitives::snark::SNARK;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize, Write, Read};
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::fs;
use std::io::{BufWriter, BufReader};
use std::path::Path;
use crate::circuits::voting::parser::*;

use super::voting_circuit::VotingCircuit;

type C = ark_ed_on_bn254::EdwardsProjective;
type GG = ark_ed_on_bn254::constraints::EdwardsVar;


use lazy_static::lazy_static;

lazy_static! {
    pub static ref PK_FILE: String = "voting.pk.dat".to_string();
    pub static ref VK_FILE: String = "voting.vk.dat".to_string();
    pub static ref PK_UNCOMP_FILE: String = "voting.pk.uncompressed.dat".to_string();
    pub static ref VK_UNCOMP_FILE: String = "voting.vk.uncompressed.dat".to_string();
    pub static ref PRF_FILE: String = "voting.proof.dat".to_string();
}


pub fn voting_setup(circuit: VotingCircuit<C, GG>) -> (ProvingKey<Bn254>, VerifyingKey<Bn254>, PreparedVerifyingKey<Bn254>) {
    let rng = &mut thread_rng();

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, rng).unwrap();

    let pvk = Groth16::<Bn254>::process_vk(&vk).unwrap();

    store_pk_vk(pk.clone(), vk.clone());

    (pk, vk, pvk)
}

pub fn store_pk_vk(pk: ProvingKey<Bn254>, vk: VerifyingKey<Bn254>) {
    let path = "./src/keys/voting/";
    let pk_file = format!("{}{}", path, PK_FILE.as_str());
    let vk_file = format!("{}{}", path, VK_FILE.as_str());
    let pk_file_uncompressed = format!("{}{}", path, PK_UNCOMP_FILE.as_str());
    let vk_file_uncompressed = format!("{}{}", path, VK_UNCOMP_FILE.as_str()); 

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();

    let mut pk_byptes_uncompressed = Vec::new();
    pk.serialize_uncompressed(&mut pk_byptes_uncompressed)
        .unwrap();

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();

    let mut vk_byptes_uncompressed = Vec::new();
    vk.serialize_uncompressed(&mut vk_byptes_uncompressed)
        .unwrap();

    fs::write(pk_file.as_str(), pk_bytes).unwrap();
    fs::write(vk_file.as_str(), vk_bytes).unwrap();
    fs::write(pk_file_uncompressed, pk_byptes_uncompressed).unwrap();
    fs::write(vk_file_uncompressed, vk_byptes_uncompressed).unwrap();
}

pub fn load_pk() -> ProvingKey<Bn254> {
    let path = "./src/keys/voting/";
    let pk_file = format!("{}{}", path, PK_FILE.as_str());

    let pk = read_proving_key(&pk_file).expect("Failed to read proving key");
    pk
}

pub fn load_vk() -> VerifyingKey<Bn254> {
    let path = "./src/keys/voting/";
    let vk_file = format!("{}{}", path, VK_FILE.as_str());

    let vk = read_verifying_key(&vk_file).expect("Failed to read verifying key");
    vk
}

pub fn read_proving_key(file_path: &str) -> Result<ProvingKey<Bn254>, ark_serialize::SerializationError> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);
    let pk = ProvingKey::<Bn254>::deserialize_compressed(&mut reader)?;
    Ok(pk)
}

pub fn read_verifying_key(file_path: &str) -> Result<VerifyingKey<Bn254>, ark_serialize::SerializationError> {
    let file = File::open(file_path)?;
    let mut reader = BufReader::new(file);
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(&mut reader)?;
    Ok(vk)
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed_on_bn254::{EdwardsProjective as C, constraints::EdwardsVar as GG};
    use crate::circuits::voting::MockingCircuit;

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
    }

    #[test]
    fn test_load_pk_vk() {
        let test_circuit = make_mocking_circuit();
        let (pk, vk, _) = voting_setup(test_circuit);

        assert!(Path::new("./src/keys/voting/voting.pk.dat").exists());
        assert!(Path::new("./src/keys/voting/voting.vk.dat").exists());

        let loaded_pk = load_pk();
        let loaded_vk = load_vk();

        // println!("vk.alpha_g1: {:?}", vk.alpha_g1);
        // println!("vk.beta_g2: {:?}", vk.beta_g2);
        // println!("vk.gamma_g2: {:?}", vk.gamma_g2);
        // println!("vk.delta_g2: {:?}", vk.delta_g2);
        // println!("vk.gamma_abc_g1: {:?}", vk.gamma_abc_g1);

        assert_eq!(pk, loaded_pk);
        assert_eq!(vk, loaded_vk);
    }
}