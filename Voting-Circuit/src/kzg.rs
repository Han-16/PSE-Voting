

use core::num;
use std::backtrace::Backtrace;
use std::path::PrefixComponent;
use std::{iter::Scan, result, vec};

use ark_bn254::{Bn254, Fq as Basefield, Fr as Scalarfield, G1Affine as GAffine, G1Projective as GPro, G2Affine as GAffine2, G1Projective as GPro2,};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, BigInteger, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::DenseUVPolynomial;
use rand::thread_rng;

// use ecfft_bn254::bn254::Bn254EcFftParameters; //라이브러리명::src::struct 

pub use ark_poly::{polynomial::univariate, EvaluationDomain, Evaluations, Radix2EvaluationDomain};

use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_ec::pairing::Pairing;

use ark_ff::Field;
use sha2::Sha256;

use std::ops::{Mul, Add}; // Mul 트레이트 임포트
use ark_poly::Polynomial;

pub use num_traits::ToPrimitive;

pub struct Person{
    name: usize,
}

pub trait intro {
    fn intro();
    
}

impl intro for Person {
    fn intro() {

    }
    
}


pub struct CRS
{
    pub d: usize, //maximum degree
    // pub g: GAffine,
    pub ck: Vec<GAffine>,
    pub ck2: Vec<GAffine2>, //[g, g^x, ..., g^(x^d)]
    pub circuit: Vec<DensePolynomial<Basefield>>, //selector polys,
    pub vanishing_polynomial: DensePolynomial<Basefield>,
}

pub trait KZGsetup {

    fn for_s1(x: &Basefield) -> Vec<Basefield>; //x >> [1,0, ...]

    fn for_s2(x: &Basefield) -> Vec<Basefield>;

    fn vanishing_polynomial(scol: &IR) -> DensePolynomial<Basefield>;

    fn setup(scol: &IR) -> Self;
    // fn selector_gen(scol: &IR) -> Vec<DensePolynomial<Basefield>>;
}

impl KZGsetup for CRS {

    fn for_s1(x: &Basefield) -> Vec<Basefield> { //x >> [1,0, ...]
        let tmp = x.into_bigint();
        let vec = BigInt::to_bits_be(&tmp); //Big-endian 즉, 높은 바이트를 가장 낮은 주소로 저장

        let mut result:Vec<Basefield> = Vec::new();
        for k in vec{
            if k == true {
                result.push(Basefield::one());
            } else if k == false {
                result.push(Basefield::zero());                
            }
            result.push(Basefield::one()); //push는 마지막으로 추가
        }

        //two mixed addtion, one equality (mixed addition 하나는 위에서 마지막 단계에 추가됨)
        result.extend(vec![Basefield::one(), Basefield::zero()]);

        //power of two
        // while (IR::is_power_of_two(result.len()) == false) {
        //     result.push(Basefield::zero());            
        // }

        return result

    }

    fn for_s2(x: &Basefield) -> Vec<Basefield> {
        let tmp = x.into_bigint();
        let vec = BigInt::to_bits_be(&tmp); //Big-endian 즉, 높은 바이트를 가장 낮은 주소로 저장
        let bits_len = vec.len();

        let mut result:Vec<Basefield> = Vec::new();
        for k in 0..bits_len{
            result.push(Basefield::one());
            result.push(Basefield::zero());
        }

        result.pop(); //마지막으로 추가되는 0 날림

        //two mixed addtion, one equality 
        result.extend(vec![Basefield::one(), Basefield::one(), Basefield::zero()]);

        //power of two
        // while (IR::is_power_of_two(result.len()) == false) {
        //     result.push(Basefield::zero());            
        // }

        return result

    }

    fn vanishing_polynomial(scol: &IR) -> DensePolynomial<Basefield> {
        // 초기 다항식은 f(x) = 1 (즉, 계수가 [1])
        let mut result_poly = DensePolynomial::from_coefficients_vec(vec![Basefield::one()]);
    
        // (x - k) 항들을 모두 곱함. 여기서 k는 1부터 scol_len까지의 값
        for k in 1..scol.Witness[0].len()+1 {
            let k_value = Basefield::from(k as u64); // k 값을 Basefield로 변환
            // (x - k) 다항식 생성
            let x_minus_k = DensePolynomial::from_coefficients_vec(vec![-k_value, Basefield::one()]);
            // 기존의 result_poly에 (x - k)를 곱함
            result_poly = IR::multiply_polynomials(&result_poly, &x_minus_k);
        }
    
        result_poly
    }

    fn setup(scol: &IR) -> Self {
        let deg = scol.Witness[0].len() * 6 + 1; //selector vector length

        let mut rng = thread_rng();
       // let gen: G1Affine = G1Affine::new_unchecked(G1_GENERATOR_X, G1_GENERATOR_Y);
        let gen1: GAffine = GAffine::rand(&mut rng); //random generator
        let gen2: GAffine2 = GAffine2::rand(&mut rng); //in G2
        let mut sk = Scalarfield::rand(&mut rng); //random scalar for commit

        let mut ck_vec: Vec<GAffine> = vec![gen1];
        let mut ck_vec2: Vec<GAffine2> = vec![gen2];

        for k in 1..deg {
            let gen2 = gen1 * sk;
            ck_vec.push(gen2.into_affine()); //g^sk, ..., g^(sk^(deg-1))
            sk *= sk;
        };

        for j in 1..deg {
            let gen2 = gen2 * sk;
            ck_vec2.push(gen2.into_affine()); //g^sk, ..., g^(sk^(deg-1))
            sk *= sk;
        }


        CRS {
             d: deg,
             ck: ck_vec,
             ck2: ck_vec2,
             circuit: IR::interpol(&scol), //selector polynomials S1(X), S2(X)
             //warning : not power of 2
             vanishing_polynomial: CRS::vanishing_polynomial(&scol),
        }
    }


}

// pub struct VotingInstance
// {
//     pub voting_round: Basefield,
//     pub root: Basefield,
//     pub vote_cm: Vec<GAffine>,
// }

// pub struct VotingWtiness
// {
//     pub sk: Basefield,
//     pub pk: GAffine,
//     pub addr: Basefield,
//     pub vote_m: Vec<Basefield>,
//     pub vote_r: Vec<Basefield>,
//     pub sn: Basefield,
//     pub leaf_pos: u32,
//     //pub tree_proof,
// }

//IR의 구조가 elliptic curve의 complete addition에 맞춰서 세팅되어있다고 가정
pub struct IR
{
    // const_num: i32, //constraints 개수
    // X1: Vec<Basefield>,
    // Y1: Vec<Basefield>,
    // Z1: Vec<Basefield>,
    // X2: Vec<Basefield>,
    // Y2: Vec<Basefield>,
    Witness: Vec<Vec<Basefield>>, //[X1, Y1, Z1, X2, Y2] or [S1, S2]
}

pub trait IRtoPoly {
    // fn Wit_length_equal(trace: &IR) -> bool;
    fn is_power_of_two(len: usize) -> bool;

    fn for_interpol_AffineX(Affine_points: &Vec<GAffine>) -> Vec<Basefield>;

    fn for_interpol_AffineY(Affine_points: &Vec<GAffine>) -> Vec<Basefield>;

    fn for_interpol_ProjX(Proj_points: &Vec<GPro>) -> Vec<Basefield>;

    fn for_interpol_ProjY(Proj_points: &Vec<GPro>) -> Vec<Basefield>;

    fn for_interpol_ProjZ(Proj_points: &Vec<GPro>) -> Vec<Basefield>;

    fn interpol(trace: &IR) -> Vec<DensePolynomial<Basefield>>;

    fn lagrange_basis_polynomial(i: usize, num_points: usize) -> DensePolynomial<Basefield>;

    fn add_polynomials(poly1: &DensePolynomial<Basefield>, poly2: &DensePolynomial<Basefield>) -> DensePolynomial<Basefield>;

    fn lagrange_interpolation_polynomial(evaluation_values: &Vec<Basefield>) -> DensePolynomial<Basefield>;

    fn multiply_polynomials(poly1: &DensePolynomial<Basefield>, poly2: &DensePolynomial<Basefield>) -> DensePolynomial<Basefield>;

    fn divide_polynomials(
        dividend: DensePolynomial<Basefield>,
        divisor: DensePolynomial<Basefield>,
    ) -> DensePolynomial<Basefield>;

    fn negate_polynomial(poly: &DensePolynomial<Basefield>) -> DensePolynomial<Basefield>;
    //fn lagrange_interpolation_polynomial(evaluation_values: &Vec<Basefield>) -> DensePolynomial<Basefield>;


}

impl IRtoPoly for IR {

    fn is_power_of_two(len: usize) -> bool { //vector길이가 2의 지수임 확인
        len > 0 && (len & (len - 1)) == 0
    }

    fn for_interpol_AffineX(Affine_points: &Vec<GAffine>) -> Vec<Basefield> {
        //Affine point들을 받아서 X좌표값들만 모음
        let mut all_X: Vec<Basefield> = vec![Basefield::zero()];

        for point in Affine_points{
            let val = point.x;
            all_X.push(val);
        }

        all_X.remove(0);

        return all_X

    }

    fn for_interpol_AffineY(Affine_points: &Vec<GAffine>) -> Vec<Basefield> {
        //Affine point들을 받아서 Y좌표값들만 모음
        let mut all_Y: Vec<Basefield> = vec![Basefield::zero()];

        for point in Affine_points{
            let val = point.y;
            all_Y.push(val);
        }

        all_Y.remove(0);

        return all_Y

    }

    fn for_interpol_ProjX(Proj_points: &Vec<GPro>) -> Vec<Basefield> {
        //Projective point들을 받아서 X좌표값들만 모음
        let mut all_X: Vec<Basefield> = vec![Basefield::zero()];

        for point in Proj_points{
            let val = point.x;
            all_X.push(val);
        }

        all_X.remove(0);

        return all_X

    }

    fn for_interpol_ProjY(Proj_points: &Vec<GPro>) -> Vec<Basefield> {
        //Projective point들을 받아서 Y좌표값들만 모음
        let mut all_Y: Vec<Basefield> = vec![Basefield::zero()];

        for point in Proj_points{
            let val = point.y;
            all_Y.push(val);
        }

        all_Y.remove(0);

        return all_Y

    }

    fn for_interpol_ProjZ(Proj_points: &Vec<GPro>) -> Vec<Basefield> {
        //Projective들을 받아서 Z좌표값들만 모음
        let mut all_Z: Vec<Basefield> = vec![Basefield::zero()];

        for point in Proj_points{
            let val = point.z;
            all_Z.push(val);
        }

        all_Z.remove(0);

        return all_Z

    }


    fn interpol(trace: &IR) -> Vec<DensePolynomial<Basefield>> {

         let trace_wit = trace.Witness.clone(); //copy
         let mut result: Vec<DensePolynomial<Basefield>> = Vec::new();
    
         let mut index = 0;

         for wit in trace_wit{
    
             let mut w_poly = IR::lagrange_interpolation_polynomial(&wit);

             result.insert(index, w_poly);
             index += 1;
         };

         result

    }

    fn lagrange_basis_polynomial(i: usize, num_points: usize) -> DensePolynomial<Basefield> {
        let mut numer_poly = DensePolynomial::from_coefficients_vec(vec![Basefield::one()]);
        let mut denom_value = Basefield::one();
        
        let xi = Basefield::from((i + 1) as u64);  // x_i = i + 1
        
        for j in 0..num_points {
            if i != j {
                let xj = Basefield::from((j + 1) as u64);  // x_j = j + 1
                let temp_numer = DensePolynomial::from_coefficients_vec(vec![-xj, Basefield::one()]);
                
                // 직접 다항식 곱셈 구현
                numer_poly = IR::multiply_polynomials(&numer_poly, &temp_numer);
                
                denom_value *= xi - xj;
            }
        }
        
        let denom_inv = denom_value.inverse().expect("Denominator inversion failed");
    
        // 분모의 역원을 포함하는 상수 다항식 생성
        let denom_poly = DensePolynomial::from_coefficients_vec(vec![denom_inv]);
        
        // 직접 다항식 곱셈 구현
        IR::multiply_polynomials(&numer_poly, &denom_poly)
    }
    
    // 두 다항식의 곱셈을 직접 구현
    fn multiply_polynomials(poly1: &DensePolynomial<Basefield>, poly2: &DensePolynomial<Basefield>) -> DensePolynomial<Basefield> {
        let coeffs1 = poly1.coeffs().to_vec();
        let coeffs2 = poly2.coeffs().to_vec();
        
        // 곱셈 결과의 차수는 두 다항식의 차수 합계 - 1
        let mut result_coeffs = vec![Basefield::zero(); coeffs1.len() + coeffs2.len() - 1];
        
        for (i, coeff1) in coeffs1.iter().enumerate() {
            for (j, coeff2) in coeffs2.iter().enumerate() {
                result_coeffs[i + j] += coeff1 * coeff2;
            }
        }
        
        DensePolynomial::from_coefficients_vec(result_coeffs)
    }
    
    fn lagrange_interpolation_polynomial(evaluation_values: &Vec<Basefield>) -> DensePolynomial<Basefield> {
        let num_points = evaluation_values.len();
        let mut interpolated_poly = DensePolynomial::zero();
        
        for (i, &yi) in evaluation_values.iter().enumerate() {
            let basis_poly = IR::lagrange_basis_polynomial(i, num_points); // l_i(x)
            let yi_poly = DensePolynomial::from_coefficients_vec(vec![yi.clone()]);
            
            // 직접 다항식 곱셈 구현
            interpolated_poly = IR::add_polynomials(&interpolated_poly, &IR::multiply_polynomials(&basis_poly, &yi_poly));
        }
        
        interpolated_poly
    }
    
    // 두 다항식의 덧셈을 직접 구현
    fn add_polynomials(poly1: &DensePolynomial<Basefield>, poly2: &DensePolynomial<Basefield>) -> DensePolynomial<Basefield> {
        let coeffs1 = poly1.coeffs().to_vec();
        let coeffs2 = poly2.coeffs().to_vec();
        
        // 결과 다항식의 차수는 두 다항식의 차수 중 큰 값에 +1
        let mut result_coeffs = vec![Basefield::zero(); std::cmp::max(coeffs1.len(), coeffs2.len())];
        
        for (i, coeff) in coeffs1.iter().enumerate() {
            result_coeffs[i] += coeff;
        }
        
        for (i, coeff) in coeffs2.iter().enumerate() {
            result_coeffs[i] += coeff;
        }
        
        DensePolynomial::from_coefficients_vec(result_coeffs)
    }

    // 두 다항식의 나눗셈을 구현 (몫과 나머지 반환)
    fn divide_polynomials(
        dividend: DensePolynomial<Basefield>,
        divisor: DensePolynomial<Basefield>,
    ) -> DensePolynomial<Basefield> {
        let mut quotient_coeffs = vec![Basefield::zero(); dividend.coeffs().len()]; // 몫의 계수들
        let mut remainder = dividend.clone(); // 나눗셈 후 남은 나머지

        let divisor_degree = divisor.degree();
        let divisor_lead_inv = divisor.coeffs()[divisor_degree].inverse().expect("Divisor's leading coefficient should have an inverse");

        while remainder.degree() >= divisor_degree && !remainder.is_zero() {
            let remainder_degree = remainder.degree();
            let lead_coeff = remainder.coeffs()[remainder_degree] * divisor_lead_inv;

            // 몫의 해당 차수의 계수는 나머지의 리딩 계수 / 나누는 다항식의 리딩 계수
            quotient_coeffs[remainder_degree - divisor_degree] = lead_coeff;

            
            let mut temp_poly = vec![Basefield::zero(); remainder_degree - divisor_degree];
            temp_poly.push(lead_coeff);
            let temp_poly = DensePolynomial::from_coefficients_vec(temp_poly);

            let subtrahend = IR::multiply_polynomials(&temp_poly, &divisor);
            remainder = IR::add_polynomials(&remainder, &IR::negate_polynomial(&subtrahend));
        }

        let quotient = DensePolynomial::from_coefficients_vec(quotient_coeffs);
        quotient
    }

    // 다항식을 음수로 변환
    fn negate_polynomial(poly: &DensePolynomial<Basefield>) -> DensePolynomial<Basefield> {
        let neg_coeffs: Vec<Basefield> = poly.coeffs().iter().map(|&coeff| -coeff).collect();
        DensePolynomial::from_coefficients_vec(neg_coeffs)
    }
    

    //circuit의 구조는 주어져있음 (circuit poly의 모양, selectors는 공개적)    
}

pub struct Prover
{
    pub crs: CRS,
    pub witness_poly: Vec<DensePolynomial<Basefield>>, 
    //X1(X), Y1(X), Z1(X), X2(X), Y2(X) + X1(1+X), Y1(1+X), Z1(1+X)
    //column X1에서 제일 첫 번째 원소를 제외하고 interpolation >>> 두 번째 원소가 1로 interpol.
}

pub trait proofgen {

    fn basefield_to_scalarfield(val: Basefield) -> Scalarfield;

    fn basevec_to_scalvec(vals: Vec<Basefield>) -> Vec<Scalarfield>;

    fn scalarfield_to_basefield(val: Scalarfield) -> Basefield;

    fn for_scalarmul_X2Y2(sk: Basefield, point: GPro) -> Vec<GAffine>;

    fn for_scalarmul_X1Y1Z1(sk: Basefield, point: GPro) -> Vec<GPro>;

    fn commit(crs: &CRS, circuit: &DensePolynomial<Basefield>) -> GAffine;
}

impl proofgen for Prover {

    fn basefield_to_scalarfield(val: Basefield) -> Scalarfield {
        let mut big_val = <Basefield as PrimeField>::into_bigint(val);
        let result = Scalarfield::from(big_val);

        result
    }

    fn scalarfield_to_basefield(val: Scalarfield) -> Basefield {
        let mut big_val = <Scalarfield as PrimeField>::into_bigint(val);
        let result = Basefield::from(big_val);

        result
    }

    fn basevec_to_scalvec(vals: Vec<Basefield>) -> Vec<Scalarfield> {
        let mut result = Vec::new();

        for k in vals{
            let mut tmp = Prover::basefield_to_scalarfield(k);
            result.push(tmp);
        }

        result
    }

    fn for_scalarmul_X2Y2(sk: Basefield, point: GPro) -> Vec<GAffine> {
        let tmp = sk.into_bigint();
        let sk_bits = BigInt::to_bits_be(&tmp);
    
        let mut points: Vec<GAffine> = Vec::new(); //for X2, Y2
    
        for k in sk_bits{
            if k == true { //1이라면 [sum ri]g의 Affine을 넣음
                points.push(point.into_affine());
            } else if k == false { //0이라면 아무것도 넣지 않음, 아무것도 넣지 않는 대신에 dummy 채움
                points.push(GAffine::identity());
            }
            points.push(GAffine::identity()); //doubling 때문에 비워지는 부분
        }
        points.pop(); //마지막 identity는 삭제되어야함

        points
    }

    fn for_scalarmul_X1Y1Z1(sk: Basefield, point: GPro) -> Vec<GPro> {
        let mut res = GPro::new_unchecked(Basefield::zero(), Basefield::from(1), Basefield::zero());

        let mut points = Vec::new(); //Vec<GPro> for X1, Y1, Z1
        let tmp = sk.into_bigint();
        let sk_bits = BigInt::to_bits_be(&tmp);
        
        points.push(res); //처음에 (0,1,0) 입력
    
        for k in sk_bits{
            if k == true { //1이라면 [sum ri]g를 이전 결과에 더한 게 입력되어야함
                res = res + point;
            } //0이라면 이전 결과값이 그대로 입력됨
            points.push(res);
    
            res = res + res; //doubling
    
            points.push(res);
        }
    
        points.pop(); //마지막 doubling 부분은 삭제

        points
    }

    
    fn commit(crs: &CRS, circuit: &DensePolynomial<Basefield>) -> GAffine {
        let mut result = GPro::zero();
        // ith coefficient - ith position
        let coeffis = circuit.coeffs(); 
        let co_vec: Vec<Basefield> = coeffis.to_vec(); //Vec<Basefield>
        let tmp = Prover::basevec_to_scalvec(co_vec);

        let commit_key = crs.ck.clone();
        
        let mut ind = 0;


        for k in 0..tmp.len() {
            let mut tmp2 = commit_key[k] * tmp[k];            
            result = result + tmp2;
        }

        result.into_affine()
        //scalar to base, base to scalar가 가능해야함
    }

}

pub struct Verifier
{
    pub crs: CRS,
}

pub trait verification {
    fn commit(crs: &CRS, circuit: &DensePolynomial<Basefield>) -> GAffine2;
}

impl verification for Verifier {
    fn commit(crs: &CRS, circuit: &DensePolynomial<Basefield>) -> GAffine2 {
        let mut result = GAffine2::zero();
        // ith coefficient - ith position
        let coeffis = circuit.coeffs(); 
        let co_vec: Vec<Basefield> = coeffis.to_vec(); //Vec<Basefield>
        let tmp = Prover::basevec_to_scalvec(co_vec);

        let commit_key = crs.ck2.clone();
        
        let mut ind = 0;


        for k in 0..tmp.len() {
            let mut tmp2 = commit_key[k] * tmp[k];            
            result = (result + tmp2).into_affine();
        }

        result
        //scalar to base, base to scalar가 가능해야함
    }
}

// |--------------------------------------|
// |S1, S2, X1, Y1, Z1, X2, Y2            |
// |bit_rep, 1                            |
// |1, 0                                  |
// |bit_rep, 1                            |
// |...            [\sum ri*x]g        ...|
// |      [\sum ri*x]g,-2[\sum ri]h       | mixed addition *[\sum ri*x]g = [\sum ri]h
// |      -[\sum ri]h, [2]g+[\sum ri]h    | mixed addition
// |                [2]g == [2]g          | dummy
// |--------------------------------------|

// S1*S2 (mixed addition) + S1*(1-S2) (doubling) + (1-S1)*S2 (Identity Addition)
// + (1-S1)*(1-S2) (equality check)

fn main(){

    //check [2]g + sk*[sum ri]g = [2]g + [sum ri]h

    let mut rng = thread_rng();
    let mut x = thread_rng();
    let mut sk = Scalarfield::rand(&mut x); //>>> Prover
    let random = Scalarfield::rand(&mut rng); //for sum ri

    let g: GAffine = GAffine::rand(&mut rng); //g
    let h = g.mul(sk); //[sk]g = h

    let sumri_g = g.mul(random); //[sum ri]g >>> Prover
    let two_g = g.mul(Scalarfield::from(2)); //[2]g
    let random_h = h.mul(random); //[sum ri]h = sk*[sum ri]g 
    let two_g_plus_random_h = two_g + random_h; //[2]g + [sum ri]h >>> Prover

    //1) CRS gen
    //Prover은 trace 행들에 첫 번째로 sk[sum ri]g를 입력 (조건)
    //warning : scalarfield가 basefield보다 modulus가 작아서 basedfield로 임베딩하는데 문제 없음
    let base_sk = Prover::scalarfield_to_basefield(sk);
    let S1 = CRS::for_s1(&base_sk);
    let S2 = CRS::for_s2(&base_sk);
    let scol = IR{Witness: vec![S1, S2]};

    let crs = CRS::setup(&scol);

    //2) Prover(witness)
    //-trace setting 
    //Prover은 trace 행들에 첫 번째로 sk[sum ri]g를 입력 (조건)
    // |S1, S2, X1, Y1, Z1, X2, Y2|
    // |bit_rep, 1                | (0,1,0) + [(X,Y) if S1 = 1, nothing if S1 = 0]
    // |1, 0                      |
    // |bit_rep, 1                |
    // |...      [\sum ri*x]g  ...|

    let tmp = sk.into_bigint();
    let sk_bits = BigInt::to_bits_be(&tmp);

    let mut X2Y2 = Prover::for_scalarmul_X2Y2(base_sk, sumri_g);
    let mut X1Y1Z1 = Prover::for_scalarmul_X1Y1Z1(base_sk, sumri_g);

    // println!("{:?}",X1Y1Z1.len());
    // println!("{:?}",X2Y2.len());
    // println!("{:?}", sk_bits.len());

    // |      [\sum ri*x]g,-2[\sum ri]h       | mixed addition *[\sum ri*x]g = [\sum ri]h
    // |      -[\sum ri]h, [2]g+[\sum ri]h    | mixed addition
    // |                [2]g == [2]g          | dummy
    // |--------------------------------------|

    let mut tmp = Scalarfield::from(-2) * sk;
    let mut _2skh = sumri_g * tmp; //-2[\sum ri]h
    X2Y2.push(_2skh.into_affine());

    tmp = Scalarfield::from(-1) * sk; //-sk
    X1Y1Z1.push(sumri_g * tmp); //-[\sum ri]h
    X2Y2.push(two_g_plus_random_h.into_affine()); //[2]g+[\sum ri]h

    // assert_eq!(two_g_plus_random_h + (sumri_g * tmp), g * Scalarfield::from(2));
    X1Y1Z1.push(two_g_plus_random_h + (sumri_g * tmp)); //[2]g 
    X2Y2.push((g * Scalarfield::from(2)).into_affine()); //[2]g 

    //interpolate witness polynomials
    //-separate X1,Y1,Z1, X2, Y2, X3, Y3, Z3
    let mut execution_trace = IR{Witness: Vec::new()};
    execution_trace.Witness.push(IR::for_interpol_ProjX(&X1Y1Z1));
    execution_trace.Witness.push(IR::for_interpol_ProjY(&X1Y1Z1));
    execution_trace.Witness.push(IR::for_interpol_ProjZ(&X1Y1Z1));

    execution_trace.Witness.push(IR::for_interpol_AffineX(&X2Y2));
    execution_trace.Witness.push(IR::for_interpol_AffineY(&X2Y2));

    X1Y1Z1.remove(0);
    execution_trace.Witness.push(IR::for_interpol_ProjX(&X1Y1Z1));
    execution_trace.Witness.push(IR::for_interpol_ProjY(&X1Y1Z1));
    execution_trace.Witness.push(IR::for_interpol_ProjZ(&X1Y1Z1));


    //-interpolate them
    let witness_poly = IR::interpol(&execution_trace);
    let pv = Prover{crs: crs, witness_poly: witness_poly};

    //set C(X)=
    // S1*S2 (mixed addition) + S1*(1-S2) (doubling) + (1-S1)*S2 (Identity Addition)
    // + (1-S1)*(1-S2) (equality check)

    // - mixed addition
    let m_S1 = IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), 
                                                            &pv.crs.circuit[0]); //-S1(X)
    let m_S2 = IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), 
                                                            &pv.crs.circuit[1]); //-S2(X)
    let one_m_S1 = IR::add_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::one()]),
                                                            &m_S1); //(1-S1(X))
    let one_m_S2 = IR::add_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::one()]),
                                                             &m_S2); //(1-S2(X))
    let S1S2 = IR::multiply_polynomials(&pv.crs.circuit[0], &pv.crs.circuit[1]); //S1(X)S2(X)4

    let mut mix_add1 = IR::multiply_polynomials(&pv.witness_poly[0], &pv.witness_poly[4])
        + IR::multiply_polynomials(&pv.witness_poly[3], &pv.witness_poly[1]);
    let mut mix_tmp1 = IR::multiply_polynomials(&pv.witness_poly[1], &pv.witness_poly[4])
        + IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-9)]), &pv.witness_poly[2]);
    let mut mix_tmp2 = IR::add_polynomials(&pv.witness_poly[1], &IR::multiply_polynomials(&pv.witness_poly[4], &pv.witness_poly[3]));
    let mut mix_tmp3 = IR::add_polynomials(&pv.witness_poly[0], &IR::multiply_polynomials(&pv.witness_poly[3], &pv.witness_poly[2]));
    let mut mix_tmp4 = IR::multiply_polynomials(&mix_tmp2, &mix_tmp3);

    mix_add1 = IR::multiply_polynomials(&mix_add1, &mix_tmp1);
    mix_add1 = mix_add1 + IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-9)]), &mix_tmp4);

    mix_add1 = mix_add1 +
            IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[5]);

    let mut mix_add2 = IR::multiply_polynomials(&pv.witness_poly[1], &pv.witness_poly[4])
        + IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(9)]), &pv.witness_poly[2]);
    mix_tmp1 = IR::multiply_polynomials(&pv.witness_poly[1], &pv.witness_poly[4])
        + IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-9)]), &pv.witness_poly[2]);
    mix_tmp2 = IR::multiply_polynomials(&pv.witness_poly[0], &pv.witness_poly[3]);
    mix_tmp3 = IR::add_polynomials(&pv.witness_poly[0], &IR::multiply_polynomials(&pv.witness_poly[3], &pv.witness_poly[2]));
    mix_tmp4 = IR::multiply_polynomials(&mix_tmp2, &mix_tmp3);

    mix_add2 = IR::multiply_polynomials(&mix_add2, &mix_tmp1);
    mix_add2 = mix_add2 + IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(27)]), &mix_tmp4);

    mix_add2 = mix_add2 +
            IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[6]);


    let mut mix_add3 = IR::add_polynomials(&pv.witness_poly[1],
        &IR::multiply_polynomials(&pv.witness_poly[4], &pv.witness_poly[2]));
    mix_tmp1 = IR::multiply_polynomials(&pv.witness_poly[1], &pv.witness_poly[4])
        + IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(9)]), &pv.witness_poly[2]);
    mix_tmp2 = IR::multiply_polynomials(&pv.witness_poly[0], &pv.witness_poly[3]);
    mix_tmp3 = IR::add_polynomials(&IR::multiply_polynomials(&pv.witness_poly[0], &pv.witness_poly[4])
        ,&IR::multiply_polynomials(&pv.witness_poly[3], &pv.witness_poly[1]));
    let mut mix_tmp4 = IR::multiply_polynomials(&mix_tmp2, &mix_tmp3);

    mix_add3 = IR::multiply_polynomials(&mix_add3, &mix_tmp1);
    mix_add3 = mix_add3 + IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(3)]), &mix_tmp4);

    mix_add2 = mix_add2 +
            IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[7]);
    
    let mix_addition = mix_add1 + mix_add2 + mix_add3;

    //-doubling
    let mut doub1 = IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(2)]), 
        &IR::multiply_polynomials(&pv.witness_poly[0], &pv.witness_poly[1]));
    let mut doub_tmp1 = IR::multiply_polynomials(&pv.witness_poly[2], &pv.witness_poly[2]);
    let mut doub_tmp2 = IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-27)]), &doub_tmp1);
    let mut doub_tmp3 = IR::multiply_polynomials(&pv.witness_poly[1], &pv.witness_poly[1]);
    let mut doub_tmp4 = IR::add_polynomials(&doub_tmp3, &doub_tmp2);

    doub1 = IR::multiply_polynomials(&doub1, &doub_tmp4);
    
    doub1 = doub1 +
    IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[5]);


    doub_tmp2 = IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-27)]), &doub_tmp1);
    doub_tmp4 = IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(9)]), &doub_tmp1);
    
    doub_tmp2 = IR::add_polynomials(&doub_tmp2, &doub_tmp3);
    let mut doub_tmp5 = IR::add_polynomials(&doub_tmp4, &doub_tmp3);
    
    doub_tmp4 = IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(24)]), 
        &doub_tmp1);
    doub_tmp4 = IR::multiply_polynomials(&doub_tmp4, &doub_tmp3);

    let mut doub2 = IR::multiply_polynomials(&doub_tmp2, &doub_tmp5);
    doub2 = doub2 + doub_tmp4;

    doub2 = doub2 +
    IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[6]);

    doub_tmp3 = IR::multiply_polynomials(&doub_tmp3, &pv.witness_poly[1]);
    let mut doub3 = IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(8)]), 
        &doub_tmp3);
    let mut doub3 = IR::multiply_polynomials(&doub3, &pv.witness_poly[2]);

    doub3 = doub3 +
    IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[7]);

    let doubling = doub1 + doub2 + doub3;

    //-Identity addition
    let mut iden1 = IR::add_polynomials(&pv.witness_poly[0], 
    &IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[5]));

    let mut iden2 = IR::add_polynomials(&pv.witness_poly[1], 
        &IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[6]));

    let mut iden3 = IR::add_polynomials(&pv.witness_poly[2], 
        &IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[7]));

    let identy_check = iden1 + iden2 +iden3;

    //-equality check
    let mut eq1 = IR::multiply_polynomials(&pv.witness_poly[3], &pv.witness_poly[2]);
    eq1 = IR::add_polynomials(&eq1,
    &IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[0]));

    let mut eq2 = IR::multiply_polynomials(&pv.witness_poly[4], &pv.witness_poly[2]);
    eq2 = IR::add_polynomials(&eq2,
    &IR::multiply_polynomials(&DensePolynomial::from_coefficients_vec(vec![Basefield::from(-1)]), &pv.witness_poly[1]));

    let equality_check = eq1 + eq2;

    //-C(X)
    // S1*S2 (mixed addition) + S1*(1-S2) (doubling) + (1-S1)*S2 (Identity Addition)
    // + (1-S1)*(1-S2) (equality check)
    let mut total_circuit = IR::multiply_polynomials(&S1S2, &mix_addition);
    total_circuit = total_circuit + 
        IR::multiply_polynomials(&IR::multiply_polynomials(&pv.crs.circuit[0], &one_m_S2), &doubling);
    total_circuit = total_circuit +
        IR::multiply_polynomials(&IR::multiply_polynomials(&one_m_S1, &pv.crs.circuit[1]), &identy_check);
    total_circuit = total_circuit +
        IR::multiply_polynomials(&IR::multiply_polynomials(&one_m_S1, &one_m_S2), &equality_check);

    let C = Prover::commit(&pv.crs, &total_circuit);
    // let a = C.x + C.y; //수정필요(직렬화 필요)

    // let hasher = <DefaultFieldHasher<Sha256> as HashToField<Basefield>>::new(&[]);
    // let preimage = a.into_bigint().to_bytes_be(); // Converting to big-endian
    // let hashes: Vec<Basefield> = hasher.hash_to_field(&preimage, 1);
    let mut vanishing = CRS::vanishing_polynomial(&scol);
    let proof = IR::divide_polynomials(total_circuit, vanishing);
    let Q = Prover::commit(&pv.crs, &proof);

    //C(X) - 0 = Q(X) \prod(X-i)
    //proof = {C, Q}

    //verification
    let v_crs = CRS::setup(&scol);
    vanishing = CRS::vanishing_polynomial(&scol);
    let V = Verifier::commit(&v_crs, &vanishing);

    //e(g^c = C, g2) = e(g^q = Q, g2^vanishing)

    let e1 = Bn254::pairing(C, v_crs.ck2[0]);
    let e2 = Bn254::pairing(Q, V);

    assert_eq!(e1, e2);
    
}



