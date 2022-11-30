/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
mod common;

use common::{MockRng, SEED};
use oberon::SecretKey;

#[test]
fn new_random_secret_key() {
    let rng = MockRng::new();
    let sk = SecretKey::new(rng);
    assert_eq!(
        sk.to_bytes(),
        [
            180, 92, 239, 44, 240, 143, 149, 163, 45, 177, 22, 179, 146, 120, 129, 229, 78, 56, 70,
            205, 251, 160, 140, 79, 159, 138, 6, 56, 250, 236, 176, 11, 70, 53, 138, 199, 245, 180,
            223, 213, 128, 166, 122, 225, 67, 58, 138, 201, 19, 114, 57, 149, 70, 141, 31, 45, 180,
            30, 208, 222, 234, 112, 21, 34, 37, 5, 163, 172, 96, 40, 81, 27, 89, 86, 163, 93, 15,
            201, 200, 183, 157, 18, 134, 140, 156, 43, 79, 231, 42, 234, 198, 139, 130, 52, 176,
            106
        ]
    );
}

#[test]
fn new_seeded_secret_key() {
    let sk = SecretKey::hash(&SEED[..]);
    assert_eq!(
        sk.to_bytes(),
        [
            16, 133, 126, 11, 192, 153, 22, 14, 53, 214, 99, 40, 66, 194, 96, 30, 19, 86, 137, 107,
            150, 49, 104, 202, 209, 80, 128, 182, 15, 154, 34, 57, 100, 51, 175, 108, 12, 56, 6,
            76, 46, 173, 247, 255, 184, 165, 228, 127, 145, 65, 171, 195, 44, 164, 3, 16, 132, 43,
            108, 82, 63, 136, 116, 3, 93, 1, 226, 152, 197, 152, 61, 212, 185, 32, 195, 211, 37,
            206, 242, 31, 72, 79, 83, 71, 197, 102, 202, 129, 95, 19, 105, 34, 22, 46, 124, 94
        ]
    )
}

#[test]
fn secret_key_from_bytes() {
    let esk = SecretKey::hash(&SEED[..]);
    let ask = SecretKey::from_bytes(&[
        16, 133, 126, 11, 192, 153, 22, 14, 53, 214, 99, 40, 66, 194, 96, 30, 19, 86, 137, 107,
        150, 49, 104, 202, 209, 80, 128, 182, 15, 154, 34, 57, 100, 51, 175, 108, 12, 56, 6, 76,
        46, 173, 247, 255, 184, 165, 228, 127, 145, 65, 171, 195, 44, 164, 3, 16, 132, 43, 108, 82,
        63, 136, 116, 3, 93, 1, 226, 152, 197, 152, 61, 212, 185, 32, 195, 211, 37, 206, 242, 31,
        72, 79, 83, 71, 197, 102, 202, 129, 95, 19, 105, 34, 22, 46, 124, 94,
    ]);
    assert_eq!(ask.is_some().unwrap_u8(), 1);
    assert_eq!(esk, ask.unwrap());
}