use std::marker::PhantomData;
use folding_schemes::utils::virtual_polynomial::{VirtualPolynomial, VPAuxInfo};
use ark_pallas::{Fr, Projective};
use folding_schemes::utils::mle::dense_vec_to_dense_mle;
use num_traits::{One, Zero};
use folding_schemes::utils::sum_check::{IOPSumCheck, SumCheck};
use std::sync::Arc;
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use ark_ff::PrimeField;
use folding_schemes::arith::r1cs::R1CS;
use folding_schemes::commitment::CommitmentScheme;
use folding_schemes::commitment::pedersen::Pedersen;
use folding_schemes::Error;
use folding_schemes::folding::nova::Witness;
use folding_schemes::transcript::poseidon::poseidon_canonical_config;
use folding_schemes::utils::vec::{dense_matrix_to_sparse, SparseMatrix};


pub fn main(){
    let mut g: VirtualPolynomial<Fr> = VirtualPolynomial::new(2);
    let temp = [Fr::zero()];
    let mle = dense_vec_to_dense_mle(2, &temp);
    let poseidon_config = poseidon_canonical_config::<Fr>();
    let mut transcript_p: PoseidonSponge<Fr> = PoseidonSponge::<Fr>::new(&poseidon_config);
    let r1cs = get_test_r1cs();
    let z = get_test_z(3);
    let (w, x) = r1cs.split_z(&z);
    let running_instance_w = Witness::<Projective>::new(w.clone(), r1cs.A.n_rows);
    let mut rng = ark_std::test_rng();
    let (pedersen_params, _) = Pedersen::<Projective>::setup(&mut rng, r1cs.A.n_cols).unwrap();

    let running_committed_instance = running_instance_w
        .commit::<Pedersen<Projective>>(&pedersen_params, x)
        .unwrap();


    let vp_aux_info = VPAuxInfo::<Fr> {
        max_degree: 2,
        num_variables: 2,
        phantom: PhantomData::<Fr>,
    };

    g.add_mle_list([Arc::new(mle.clone()), Arc::new(mle.clone())], Fr::one()).expect("TODO: panic message");

    let sumcheck_proof = IOPSumCheck::<Fr,
        PoseidonSponge<Fr>>::prove(&g, &mut transcript_p)
        .map_err(|err| Error::SumCheckProveError(err.to_string())).unwrap();

    let sumcheck_subclaim =
        IOPSumCheck::<Fr, PoseidonSponge<Fr>>::verify(running_committed_instance.x[0], &sumcheck_proof, &vp_aux_info, &mut transcript_p)
            .map_err(|err| Error::SumCheckVerifyError(err.to_string()));
}

pub fn get_test_r1cs<F: PrimeField>() -> R1CS<F> {
    // R1CS for: x^3 + x + 5 = y (example from article
    // https://www.vitalik.ca/general/2016/12/10/qap.html )
    let A = to_F_matrix::<F>(vec![
        vec![0, 1, 0, 0, 0, 0],
        vec![0, 0, 0, 1, 0, 0],
        vec![0, 1, 0, 0, 1, 0],
        vec![5, 0, 0, 0, 0, 1],
    ]);
    let B = to_F_matrix::<F>(vec![
        vec![0, 1, 0, 0, 0, 0],
        vec![0, 1, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0],
        vec![1, 0, 0, 0, 0, 0],
    ]);
    let C = to_F_matrix::<F>(vec![
        vec![0, 0, 0, 1, 0, 0],
        vec![0, 0, 0, 0, 1, 0],
        vec![0, 0, 0, 0, 0, 1],
        vec![0, 0, 1, 0, 0, 0],
    ]);

    R1CS::<F> { l: 1, A, B, C }
}

pub fn get_test_z<F: PrimeField>(input: usize) -> Vec<F> {
    // z = (1, io, w)
    to_F_vec(vec![
        1,
        input,                             // io
        input * input * input + input + 5, // x^3 + x + 5
        input * input,                     // x^2
        input * input * input,             // x^2 * x
        input * input * input + input,     // x^3 + x
    ])
}

pub fn to_F_matrix<F: PrimeField>(M: Vec<Vec<usize>>) -> SparseMatrix<F> {
    dense_matrix_to_sparse(to_F_dense_matrix(M))
}
pub fn to_F_dense_matrix<F: PrimeField>(M: Vec<Vec<usize>>) -> Vec<Vec<F>> {
    M.iter()
        .map(|m| m.iter().map(|r| F::from(*r as u64)).collect())
        .collect()
}
pub fn to_F_vec<F: PrimeField>(z: Vec<usize>) -> Vec<F> {
    z.iter().map(|c| F::from(*c as u64)).collect()
}