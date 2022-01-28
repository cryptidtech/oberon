/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
mod common;

use common::{MockRng, ID};
use oberon::{Blinding, Proof, PublicKey, SecretKey};
use rand_core::RngCore;
use subtle::Choice;

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
    assert_eq!(
        proof.to_bytes(),
        [
            172, 145, 178, 159, 102, 213, 216, 1, 67, 7, 181, 188, 21, 214, 183, 93, 94, 231, 162,
            171, 68, 76, 26, 198, 205, 17, 128, 243, 177, 204, 38, 197, 40, 13, 155, 87, 203, 253,
            136, 66, 23, 116, 244, 10, 205, 255, 58, 195, 161, 33, 200, 178, 70, 39, 11, 104, 47,
            232, 103, 117, 135, 223, 35, 106, 31, 95, 127, 207, 25, 10, 9, 141, 188, 15, 41, 230,
            211, 176, 234, 71, 186, 63, 70, 112, 168, 29, 85, 142, 12, 184, 101, 248, 80, 212, 222,
            32, 174, 30, 113, 77, 126, 55, 211, 16, 193, 198, 211, 189, 231, 238, 207, 219, 158,
            27, 44, 22, 86, 171, 197, 79, 158, 97, 234, 48, 117, 241, 33, 199, 17, 84, 42, 57, 254,
            39, 126, 230, 105, 224, 184, 138, 101, 149, 204, 79, 15, 221, 242, 66, 212, 190, 125,
            156, 175, 210, 75, 48, 91, 200, 173, 144, 234, 44, 63, 192, 146, 127, 49, 236, 147, 70,
            11, 72, 6, 85, 158, 94, 130, 141, 60, 69, 95, 236, 14, 173, 92, 54, 130, 73, 141, 15,
            64, 39, 219, 125, 28, 246, 176, 46, 66, 232, 25, 74, 86, 114, 92, 216, 126, 28, 140,
            126, 92, 253, 164, 60, 177, 215, 122, 47, 44, 26, 227, 0, 169, 23, 234, 130, 106, 152,
            241, 54, 235, 151, 186, 169, 30, 193, 169, 67, 131, 218, 214, 15, 128, 127, 35, 235,
            189, 41, 199, 117, 169, 32, 249, 176, 0, 107
        ]
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
