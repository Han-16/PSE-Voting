use serde::{Serialize, Deserialize};
use std::fs;
use serde_json::Result;
use ark_ec::CurveGroup;
use std::str::FromStr;

type C = ark_ed_on_bn254::EdwardsProjective;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct User {
    pub sk: String,
    pub pk: Vec<String>,
    pub addr: String,
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
struct MockData {
    g: Vec<String>,
    x: String,
    ck: Vec<Vec<String>>,
    Users: Vec<User>,
}

#[derive(Debug, Clone)]
pub struct ParsedUser {
    pub sk: <C as CurveGroup>::BaseField,
    pub pk: <C as CurveGroup>::Affine,
    pub addr: <C as CurveGroup>::BaseField,
}

fn read_mock_data() -> Result<MockData> {
    let data: String = fs::read_to_string("src/circuits/Mock.json").expect("Unable to read Mock.json file");
    let mock_data: MockData = serde_json::from_str(&data)?;
    Ok(mock_data)
}

fn from_base_field_to_affine(x: &str, y: &str) -> Result<<C as CurveGroup>::Affine> {
    let x = <<C as CurveGroup>::BaseField>::from_str(x).unwrap();
    let y = <<C as CurveGroup>::BaseField>::from_str(y).unwrap();
    Ok(<<C as CurveGroup>::Affine>::new(x, y))
}

pub fn get_users() -> Result<Vec<User>> {
    let mock_data = read_mock_data()?;
    Ok(mock_data.Users)
}

pub fn get_user() -> Result<User> {
    let users = get_users()?;
    Ok(users[0].clone())
}

pub fn get_g() -> Result<<C as CurveGroup>::Affine> {
    let mock_data = read_mock_data()?;
    let g_x = &mock_data.g[0];
    let g_y = &mock_data.g[1];
    let g = from_base_field_to_affine(g_x, g_y)?;
    Ok(g)
}

pub fn get_ck() -> Result<Vec<<C as CurveGroup>::Affine>> {
    let mock_data = read_mock_data()?;
    let ck_0_x = &mock_data.ck[0][0];
    let ck_0_y = &mock_data.ck[0][1];
    let ck_1_x = &mock_data.ck[1][0];
    let ck_1_y = &mock_data.ck[1][1];
    let ck_0 = from_base_field_to_affine(ck_0_x, ck_0_y)?;
    let ck_1 = from_base_field_to_affine(ck_1_x, ck_1_y)?;
    Ok(vec![ck_0, ck_1])
}

pub fn get_x() -> Result<<C as CurveGroup>::BaseField> {
    let mock_data = read_mock_data()?;
    let x_str = mock_data.x;
    let x = <<C as CurveGroup>::BaseField>::from_str(&x_str).unwrap();
    Ok(x)
}

pub fn parse_user(user: &User) -> Result<ParsedUser> {
    let sk = <<C as CurveGroup>::BaseField>::from_str(&user.sk).unwrap();
    let addr = <<C as CurveGroup>::BaseField>::from_str(&user.addr).unwrap();
    let pk_x = &user.pk[0];
    let pk_y = &user.pk[1];
    let pk = from_base_field_to_affine(pk_x, pk_y)?;

    Ok(ParsedUser { sk, pk, addr })
}

pub fn parse_all_users() -> Result<Vec<ParsedUser>> {
    let users = get_users()?;
    users.iter().map(|user| parse_user(user)).collect()
}