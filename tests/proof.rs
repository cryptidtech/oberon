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
}
