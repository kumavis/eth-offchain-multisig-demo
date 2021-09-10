/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

use wasm_bindgen::prelude::*;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate rand;
extern crate zeroize;

extern crate cryptoxide;

pub mod curv;
pub mod gg_2018;
pub mod paillier;

use curv::arithmetic::num_bigint::from;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::Hash;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use curv::elliptic::curves::traits::*;
use gg_2018::mta::*;
use gg_2018::party_i::*;

type MultiKey = (Vec<Keys>, Vec<SharedKeys>, Vec<GE>, GE, VerifiableSS);

#[derive(Serialize, Deserialize)]
pub struct SignOutput {
    local_sig_vec: Vec<LocalSignature>,
    r_vec: Vec<GE>,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}

#[cfg(target_arch = "wasm32")]
extern crate wasm_bindgen;

#[cfg(all(test, target_arch = "wasm32"))]
extern crate wasm_bindgen_test;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    console_log!("WASM: module started.");
}

#[wasm_bindgen]
pub fn keygen(t: usize, n: usize) -> JsValue {
    console_log!("WASM: creating keys...");
    let key_data = keygen_t_n_parties(t, n);
    console_log!("WASM: key generation complete.");
    JsValue::from_serde(&key_data).unwrap()
}

#[wasm_bindgen]
pub fn sign_message(t: usize, keys: JsValue, message: JsValue, sign_indices: JsValue) -> JsValue {
    console_log!("WASM: sign message...");
    let keys: MultiKey = keys.into_serde().unwrap();
    let message: Vec<u8> = message.into_serde().unwrap();
    let mut sign_indices: Vec<usize> = sign_indices.into_serde().unwrap();
    sign_indices.sort();
    let sign_output = sign(keys, t, sign_indices.len(), sign_indices, message);
    console_log!("WASM: message signing complete.");
    JsValue::from_serde(&sign_output).unwrap()
}

#[wasm_bindgen]
pub fn verify_signature(ttag: usize, sign_output: JsValue) {
    console_log!("WASM: verify signature...");
    let sign_output: SignOutput = sign_output.into_serde().unwrap();
    verify(ttag, sign_output);
    console_log!("WASM: signature verification complete.");
}

pub fn keygen_t_n_parties(t: usize, n: usize) -> MultiKey {
    let parames = Parameters {
        threshold: t,
        share_count: n.clone(),
    };
    let party_keys_vec = (0..n.clone())
        .map(|i| Keys::create(i))
        .collect::<Vec<Keys>>();

    let mut bc1_vec = Vec::new();
    let mut decom_vec = Vec::new();
    for i in 0..n.clone() {
        let (bc1, decom1) = party_keys_vec[i].phase1_broadcast_phase3_proof_of_correct_key();
        bc1_vec.push(bc1);
        decom_vec.push(decom1);
    }

    let y_vec = (0..n.clone())
        .map(|i| decom_vec[i].y_i.clone())
        .collect::<Vec<GE>>();
    let mut y_vec_iter = y_vec.iter();
    let head = y_vec_iter.next().unwrap();
    let tail = y_vec_iter;
    let y_sum = tail.fold(head.clone(), |acc, x| acc + x);
    let mut vss_scheme_vec = Vec::new();
    let mut secret_shares_vec = Vec::new();
    let mut index_vec = Vec::new();
    for i in 0..n.clone() {
        let (vss_scheme, secret_shares, index) = party_keys_vec[i]
            .phase1_verify_com_phase3_verify_correct_key_phase2_distribute(
                &parames, &decom_vec, &bc1_vec,
            )
            .expect("invalid key");
        vss_scheme_vec.push(vss_scheme);
        secret_shares_vec.push(secret_shares);
        index_vec.push(index);
    }
    let vss_scheme_for_test = vss_scheme_vec.clone();

    let party_shares = (0..n.clone())
        .map(|i| {
            (0..n.clone())
                .map(|j| {
                    let vec_j = &secret_shares_vec[j];
                    vec_j[i].clone()
                })
                .collect::<Vec<FE>>()
        })
        .collect::<Vec<Vec<FE>>>();

    let mut shared_keys_vec = Vec::new();
    let mut dlog_proof_vec = Vec::new();
    for i in 0..n.clone() {
        let (shared_keys, dlog_proof) = party_keys_vec[i]
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &parames,
                &y_vec,
                &party_shares[i],
                &vss_scheme_vec,
                &(&index_vec[i] + 1),
            )
            .expect("invalid vss");
        shared_keys_vec.push(shared_keys);
        dlog_proof_vec.push(dlog_proof);
    }

    let pk_vec = (0..n.clone())
        .map(|i| dlog_proof_vec[i].pk.clone())
        .collect::<Vec<GE>>();

    //both parties run:
    Keys::verify_dlog_proofs(&parames, &dlog_proof_vec, &y_vec).expect("bad dlog proof");

    //test
    let xi_vec = (0..t.clone() + 1)
        .map(|i| shared_keys_vec[i].x_i.clone())
        .collect::<Vec<FE>>();
    let x = vss_scheme_for_test[0]
        .clone()
        .reconstruct(&index_vec[0..t.clone() + 1], &xi_vec);
    let sum_u_i = party_keys_vec
        .iter()
        .fold(FE::zero(), |acc, x| acc + &x.u_i);
    assert_eq!(x, sum_u_i);

    (
        party_keys_vec,
        shared_keys_vec,
        pk_vec,
        y_sum,
        vss_scheme_for_test[0].clone(),
    )
}

#[allow(dead_code)]
pub fn sign(keys: MultiKey, t: usize, ttag: usize, s: Vec<usize>, message: Vec<u8>) -> SignOutput {
    let (party_keys_vec, shared_keys_vec, _pk_vec, y, vss_scheme) = keys;

    let private_vec = (0..shared_keys_vec.len())
        .map(|i| PartyPrivate::set_private(party_keys_vec[i].clone(), shared_keys_vec[i].clone()))
        .collect::<Vec<PartyPrivate>>();
    // make sure that we have t<t'<n and the group s contains id's for t' parties
    // TODO: make sure s has unique id's and they are all in range 0..n
    // TODO: make sure this code can run when id's are not in ascending order
    assert!(ttag > t);
    assert_eq!(s.len(), ttag);

    // each party creates a signing key. This happens in parallel IRL. In this test we
    // create a vector of signing keys, one for each party.
    // throughout i will index parties
    let sign_keys_vec = (0..ttag)
        .map(|i| {
            SignKeys::create(&private_vec[s[i]], &vss_scheme, s[i], &s)
        })
        .collect::<Vec<SignKeys>>();

    // each party computes [Ci,Di] = com(g^gamma_i) and broadcast the commitments
    let mut bc1_vec = Vec::new();
    let mut decommit_vec1 = Vec::new();
    for i in 0..ttag.clone() {
        let (com, decommit_phase_1) = sign_keys_vec[i].phase1_broadcast();
        bc1_vec.push(com);
        decommit_vec1.push(decommit_phase_1);
    }

    // each party i sends encryption of k_i under her Paillier key
    // m_a_vec = [ma_0;ma_1;,...]
    let mut m_a_vec = Vec::new();
    for i in 0..ttag.clone() {
        let m_a_k = MessageA::a(&sign_keys_vec[i].k_i, &party_keys_vec[s[i]].ek);

        m_a_vec.push(m_a_k);
    }

    // each party i sends responses to m_a_vec she received (one response with input gamma_i and one with w_i)
    // m_b_gamma_vec_all is a matrix where column i is a vector of message_b's that party i answers to all ma_{j!=i} using paillier key of party j to answer to ma_j

    // aggregation of the n messages of all parties
    let mut m_b_gamma_vec_all = Vec::new();
    let mut beta_vec_all = Vec::new();
    let mut m_b_w_vec_all = Vec::new();
    let mut ni_vec_all = Vec::new();

    for i in 0..ttag.clone() {
        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };

            let (m_b_gamma, beta_gamma) = MessageB::b(
                &sign_keys_vec[i].gamma_i,
                &party_keys_vec[s[ind]].ek,
                m_a_vec[ind].clone(),
            );
            let (m_b_w, beta_wi) = MessageB::b(
                &sign_keys_vec[i].w_i,
                &party_keys_vec[s[ind]].ek,
                m_a_vec[ind].clone(),
            );

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }
        m_b_gamma_vec_all.push(m_b_gamma_vec.clone());
        beta_vec_all.push(beta_vec.clone());
        m_b_w_vec_all.push(m_b_w_vec.clone());
        ni_vec_all.push(ni_vec.clone());
    }

    // Here we complete the MwA protocols by taking the mb matrices and starting with the first column generating the appropriate message
    // for example for index i=0 j=0 we need party at index s[1] to answer to mb that party s[0] sent, completing a protocol between s[0] and s[1].
    //  for index i=1 j=0 we need party at index s[0] to answer to mb that party s[1]. etc.
    // IRL each party i should get only the mb messages that other parties sent in response to the party i ma's.
    // TODO: simulate as IRL
    let mut alpha_vec_all = Vec::new();
    let mut miu_vec_all = Vec::new();

    for i in 0..ttag.clone() {
        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();

        let m_b_gamma_vec_i = &m_b_gamma_vec_all[i];
        let m_b_w_vec_i = &m_b_w_vec_all[i];

        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            let m_b = m_b_gamma_vec_i[j].clone();

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&party_keys_vec[s[ind]].dk, &sign_keys_vec[ind].k_i)
                .expect("wrong dlog or m_b");
            let m_b = m_b_w_vec_i[j].clone();
            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&party_keys_vec[s[ind]].dk, &sign_keys_vec[ind].k_i)
                .expect("wrong dlog or m_b");

            // since we actually run two MtAwc each party needs to make sure that the values B are the same as the public values
            // here for b=w_i the parties already know W_i = g^w_i  for each party so this check is done here. for b = gamma_i the check will be later when g^gamma_i will become public
            // currently we take the W_i from the other parties signing keys
            // TODO: use pk_vec (first change from x_i to w_i) for this check.
            assert_eq!(m_b.b_proof.pk.clone(), sign_keys_vec[i].g_w_i.clone());

            alpha_vec.push(alpha_ij_gamma);
            miu_vec.push(alpha_ij_wi);
        }
        alpha_vec_all.push(alpha_vec.clone());
        miu_vec_all.push(miu_vec.clone());
    }

    let mut delta_vec = Vec::new();
    let mut sigma_vec = Vec::new();

    for i in 0..ttag.clone() {
        let delta = sign_keys_vec[i].phase2_delta_i(&alpha_vec_all[i], &beta_vec_all[i]);
        let sigma = sign_keys_vec[i].phase2_sigma_i(&miu_vec_all[i], &ni_vec_all[i]);
        delta_vec.push(delta);
        sigma_vec.push(sigma);
    }

    // all parties broadcast delta_i and compute delta_i ^(-1)
    let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);

    // de-commit to g^gamma_i from phase1, test comm correctness, and that it is the same value used in MtA.
    // Return R

    let _g_gamma_i_vec = (0..ttag)
        .map(|i| sign_keys_vec[i].g_gamma_i.clone())
        .collect::<Vec<GE>>();

    let r_vec = (0..ttag)
        .map(|_| {
            // each party i tests all B = g^b = g ^ gamma_i she received.
            let b_proof_vec = (0..ttag)
                .map(|j| {
                    let b_gamma_vec = &m_b_gamma_vec_all[j];
                    &b_gamma_vec[0].b_proof
                })
                .collect::<Vec<&DLogProof>>();
            let r = SignKeys::phase4(&delta_inv, &b_proof_vec, decommit_vec1.clone(), &bc1_vec)
                .expect("bad gamma_i decommit");
            r
        })
        .collect::<Vec<GE>>();

    let message_bn = HSha256::create_hash(&vec![&from(&message[..])]);
    let mut local_sig_vec = Vec::new();

    // each party computes s_i but don't send it yet. we start with phase5
    for i in 0..ttag.clone() {
        let local_sig = LocalSignature::phase5_local_sig(
            &sign_keys_vec[i].k_i,
            &message_bn,
            &r_vec[i],
            &sigma_vec[i],
            &y,
        );
        local_sig_vec.push(local_sig);
    }

    SignOutput {
        local_sig_vec,
        r_vec,
    }
}

pub fn verify(ttag: usize, sign_output: SignOutput) {
    let SignOutput {
        local_sig_vec,
        r_vec,
    } = sign_output;

    let mut phase5_com_vec: Vec<Phase5Com1> = Vec::new();
    let mut phase_5a_decom_vec: Vec<Phase5ADecom1> = Vec::new();
    let mut helgamal_proof_vec = Vec::new();
    // we notice that the proof for V= R^sg^l, B = A^l is a general form of homomorphic elgamal.
    for i in 0..ttag.clone() {
        let (phase5_com, phase_5a_decom, helgamal_proof) =
            local_sig_vec[i].phase5a_broadcast_5b_zkproof();
        phase5_com_vec.push(phase5_com);
        phase_5a_decom_vec.push(phase_5a_decom);
        helgamal_proof_vec.push(helgamal_proof);
    }

    let mut phase5_com2_vec = Vec::new();
    let mut phase_5d_decom2_vec = Vec::new();
    for i in 0..ttag.clone() {
        let mut phase_5a_decom_vec_clone = phase_5a_decom_vec.clone();
        let mut phase_5a_com_vec_clone = phase5_com_vec.clone();
        let mut phase_5b_elgamal_vec_clone = helgamal_proof_vec.clone();

        let _decom_i = phase_5a_decom_vec_clone.remove(i);
        let _com_i = phase_5a_com_vec_clone.remove(i);
        let _elgamal_i = phase_5b_elgamal_vec_clone.remove(i);
        //        for j in 0..s_minus_i.len() {
        let (phase5_com2, phase_5d_decom2) = local_sig_vec[i]
            .phase5c(
                &phase_5a_decom_vec_clone,
                &phase_5a_com_vec_clone,
                &phase_5b_elgamal_vec_clone,
                &phase_5a_decom_vec[i].V_i,
                &r_vec[0],
            )
            .expect("error phase5");
        phase5_com2_vec.push(phase5_com2);
        phase_5d_decom2_vec.push(phase_5d_decom2);
        //        }
    }

    // assuming phase5 checks passes each party sends s_i and compute sum_i{s_i}
    let mut s_vec: Vec<FE> = Vec::new();
    for i in 0..ttag.clone() {
        let s_i = local_sig_vec[i]
            .phase5d(&phase_5d_decom2_vec, &phase5_com2_vec, &phase_5a_decom_vec)
            .expect("bad com 5d");
        s_vec.push(s_i);
    }

    // here we compute the signature only of party i=0 to demonstrate correctness.
    s_vec.remove(0);
    let _sig = local_sig_vec[0]
        .output_signature(&s_vec)
        .expect("verification failed");
}
