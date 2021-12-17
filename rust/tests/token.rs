/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
mod common;

use common::{MockRng, ID};
use oberon::{PublicKey, SecretKey, Token};

#[test]
fn valid_token() {
    let sk = SecretKey::new(MockRng::new());
    let pk = PublicKey::from(&sk);
    let opt_token = sk.sign(ID);

    assert!(opt_token.is_some());
    let token = opt_token.unwrap();
    assert_eq!(token.verify(pk, ID).unwrap_u8(), 1u8);
    assert_eq!(token.verify(pk, b"wrong identity").unwrap_u8(), 0u8);
}

#[test]
fn token_from_bytes() {
    let sk = SecretKey::new(MockRng::new());
    let exp_token = sk.sign(ID).unwrap();
    let opt_act_token = Token::from_bytes(&[
        174, 221, 77, 7, 147, 66, 236, 180, 112, 106, 14, 104, 35, 123, 13, 189, 211, 158, 32, 194,
        24, 50, 49, 93, 87, 126, 102, 20, 192, 132, 157, 221, 83, 98, 81, 93, 155, 137, 134, 9, 58,
        108, 30, 237, 108, 13, 40, 242,
    ]);
    assert_eq!(opt_act_token.is_some().unwrap_u8(), 1u8);
    let act_token = opt_act_token.unwrap();
    assert_eq!(act_token, exp_token);
}
