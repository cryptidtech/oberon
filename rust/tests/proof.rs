/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
mod common;

use common::{MockRng, ID};
use oberon::{Blinding, Proof, PublicKey, SecretKey};
use rand_core::RngCore;

#[test]
fn proof_works() {
    let mut rng = MockRng::new();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from(&sk);
    let token = sk.sign(ID).unwrap();
    let blinding = Blinding::new(b"1234");
    let blinded_token = token - &blinding;

    // sent from verifier, could also be a timestamp in milliseconds as unsigned 8 byte integer
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);

    let opt_proof = Proof::new(&blinded_token, &[blinding], ID, &nonce, &mut rng);
    assert!(opt_proof.is_some());
    let proof = opt_proof.unwrap();

    // Send proof, id, nonce to verifier
    assert_eq!(proof.open(pk, ID, nonce).unwrap_u8(), 1u8);
    assert_eq!(proof.open(pk, b"wrong id", nonce).unwrap_u8(), 0u8);
    assert_eq!(proof.open(pk, ID, b"wrong nonce").unwrap_u8(), 0u8);

    // check proof serde
    let proof_bytes = proof.to_bytes();
    let opt_proof = Proof::from_bytes(&proof_bytes);
    assert_eq!(opt_proof.is_some().unwrap_u8(), 1u8);
    let proof = opt_proof.unwrap();
    assert_eq!(proof.open(pk, ID, nonce).unwrap_u8(), 1u8);

    // No blinding factor
    let opt_proof = Proof::new(&blinded_token, &[], ID, &nonce, &mut rng);
    assert!(opt_proof.is_some());
    let proof = opt_proof.unwrap();

    // Send proof, id, nonce to verifier
    assert_eq!(proof.open(pk, ID, nonce).unwrap_u8(), 0u8);

    // proof to bytes
    println!("{:?}", proof.to_bytes());
    assert_eq!(
        proof.to_bytes(),
        [
            171, 50, 166, 43, 168, 199, 83, 254, 187, 82, 10, 20, 80, 106, 217, 99, 152, 85, 146,
            201, 116, 160, 65, 177, 74, 89, 56, 163, 249, 54, 78, 230, 45, 98, 181, 248, 14, 40,
            206, 168, 136, 107, 154, 224, 116, 86, 210, 236, 160, 236, 124, 238, 208, 209, 161, 12,
            122, 2, 17, 55, 18, 187, 110, 106, 177, 222, 130, 252, 100, 226, 32, 255, 118, 230,
            179, 233, 49, 240, 51, 248, 199, 92, 53, 218, 200, 163, 69, 13, 111, 255, 189, 151, 65,
            122, 150, 192
        ]
    )
}

#[test]
fn serialization_test() {
    let ct_proof = Proof::from_bytes(&[
        171, 50, 166, 43, 168, 199, 83, 254, 187, 82, 10, 20, 80, 106, 217, 99, 152, 85, 146, 201,
        116, 160, 65, 177, 74, 89, 56, 163, 249, 54, 78, 230, 45, 98, 181, 248, 14, 40, 206, 168,
        136, 107, 154, 224, 116, 86, 210, 236, 160, 236, 124, 238, 208, 209, 161, 12, 122, 2, 17,
        55, 18, 187, 110, 106, 177, 222, 130, 252, 100, 226, 32, 255, 118, 230, 179, 233, 49, 240,
        51, 248, 199, 92, 53, 218, 200, 163, 69, 13, 111, 255, 189, 151, 65, 122, 150, 192,
    ]);
    assert_eq!(ct_proof.is_some().unwrap_u8(), 1u8);
    let proof = ct_proof.unwrap();
    let s = serde_json::to_string(&proof).unwrap();
    println!("len = {}", s.len());
    println!("json = {:#?}", s);
    println!(
        "cbor = {}",
        hex::encode(&serde_bare::to_vec(&proof).unwrap())
    );
}

#[test]
fn vectors() {
    let mut rng = MockRng::new();
    let sk = SecretKey::new(&mut rng);
    let pk = PublicKey::from(&sk);
    let id = hex::decode("aa").unwrap();
    let token = sk.sign(&id).unwrap();
    let mut nonce = [0u8; 16];
    rng.fill_bytes(&mut nonce);
    let proof = Proof::new(&token, &[], &id, nonce, &mut rng).unwrap();
    println!("sk    = {}", hex::encode(sk.to_bytes()));
    println!("token = {}", hex::encode(token.to_bytes()));
    println!("nonce = {}", hex::encode(nonce));
    println!("proof = {}", hex::encode(proof.to_bytes()));
    println!("open = {}", proof.open(pk, &id, nonce).unwrap_u8())
}
