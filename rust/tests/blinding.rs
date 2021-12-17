/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
mod common;

use common::{MockRng, ID};
use oberon::{Blinding, SecretKey};

#[test]
fn blinding_works() {
    let blinding = Blinding::new(b"1234");
    let sk = SecretKey::new(MockRng::new());
    let token = sk.sign(ID).unwrap();
    assert_ne!(blinding.to_bytes(), [0u8; 48]);
    let blinded_token = &token - &blinding;
    assert_ne!(token, blinded_token);
    assert_eq!(token, &blinded_token + &blinding);

    // null blinding
    let blinding = Blinding::new(b"");
    let sk = SecretKey::new(MockRng::new());
    let token = sk.sign(ID).unwrap();
    assert_ne!(blinding.to_bytes(), [0u8; 48]);
    let blinded_token = &token - &blinding;
    assert_ne!(token, blinded_token);
    assert_eq!(token, &blinded_token + &blinding);
}
