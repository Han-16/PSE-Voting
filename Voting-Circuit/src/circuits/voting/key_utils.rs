use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use std::fs::File;
use std::fs;
use std::io::BufReader;




use lazy_static::lazy_static;

lazy_static! {
    pub static ref PK_FILE: String = "voting.pk.dat".to_string();
    pub static ref VK_FILE: String = "voting.vk.dat".to_string();
    pub static ref PK_UNCOMP_FILE: String = "voting.pk.uncompressed.dat".to_string();
    pub static ref VK_UNCOMP_FILE: String = "voting.vk.uncompressed.dat".to_string();
    pub static ref PRF_FILE: String = "voting.proof.dat".to_string();
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