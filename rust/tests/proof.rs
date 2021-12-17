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
            172, 44, 196, 169, 160, 26, 52, 127, 53, 59, 189, 108, 9, 32, 254, 37, 75, 107, 18, 84,
            126, 229, 137, 64, 94, 84, 198, 224, 51, 47, 129, 95, 172, 142, 27, 206, 212, 176, 121,
            124, 0, 121, 27, 210, 138, 46, 62, 32, 171, 50, 166, 43, 168, 199, 83, 254, 187, 82,
            10, 20, 80, 106, 217, 99, 152, 85, 146, 201, 116, 160, 65, 177, 74, 89, 56, 163, 249,
            54, 78, 230, 45, 98, 181, 248, 14, 40, 206, 168, 136, 107, 154, 224, 116, 86, 210, 236
        ]
    );
}
