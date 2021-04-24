/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
mod common;

use common::{MockRng, SEED};
use oberon::{PublicKey, SecretKey};

#[test]
fn new_random_public_key() {
    let rng = MockRng::new();
    let sk = SecretKey::new(rng);
    let pk = PublicKey::from(&sk);
    assert_eq!(
        pk.to_bytes(),
        [
            179, 2, 6, 45, 239, 85, 45, 114, 170, 112, 126, 208, 90, 215, 179, 26, 11, 176, 144,
            41, 15, 193, 255, 233, 143, 170, 15, 56, 238, 202, 106, 80, 78, 237, 239, 171, 83, 49,
            110, 245, 97, 185, 166, 210, 249, 175, 138, 99, 16, 210, 181, 179, 160, 67, 31, 64,
            150, 118, 94, 150, 255, 219, 120, 116, 8, 82, 115, 169, 172, 209, 210, 0, 251, 2, 144,
            67, 22, 195, 77, 233, 65, 94, 181, 131, 178, 50, 103, 60, 153, 177, 70, 226, 211, 181,
            202, 184, 130, 142, 133, 245, 219, 22, 200, 148, 241, 229, 69, 91, 93, 229, 18, 242,
            13, 174, 216, 11, 153, 103, 255, 84, 237, 67, 225, 42, 161, 83, 133, 52, 72, 99, 90,
            158, 169, 19, 170, 61, 105, 217, 226, 199, 144, 119, 138, 87, 16, 187, 136, 160, 199,
            47, 217, 238, 234, 30, 95, 28, 110, 4, 133, 199, 34, 17, 120, 45, 97, 27, 254, 223,
            253, 68, 53, 122, 100, 226, 236, 202, 201, 61, 95, 58, 14, 117, 165, 94, 69, 140, 85,
            85, 92, 188, 141, 49, 139, 205, 201, 238, 245, 185, 200, 112, 157, 191, 241, 64, 100,
            189, 36, 57, 146, 181, 230, 211, 95, 147, 113, 195, 197, 189, 104, 208, 155, 73, 108,
            25, 215, 253, 192, 73, 94, 148, 89, 60, 223, 105, 194, 160, 18, 59, 186, 19, 22, 143,
            40, 178, 135, 124, 20, 215, 44, 183, 89, 5, 138, 69, 186, 249, 203, 119, 101, 39, 79,
            237, 182, 160, 160, 151, 213, 205, 211, 130, 186, 223, 59, 83, 178, 132, 53, 174, 246,
            49, 20, 79, 165, 202, 217, 129, 192, 197
        ]
    );
}

#[test]
fn new_seeded_public_key() {
    let sk = SecretKey::hash(&SEED[..]);
    let pk = PublicKey::from(&sk);
    assert_eq!(
        pk.to_bytes(),
        [
            180, 38, 11, 239, 38, 13, 55, 164, 241, 71, 116, 212, 199, 63, 84, 180, 147, 139, 93,
            230, 92, 253, 51, 91, 148, 102, 103, 112, 252, 187, 0, 198, 76, 156, 221, 125, 188, 60,
            106, 240, 171, 134, 4, 43, 181, 132, 243, 86, 19, 131, 35, 193, 11, 141, 217, 90, 126,
            18, 252, 181, 92, 113, 11, 133, 62, 134, 83, 59, 40, 90, 149, 137, 10, 244, 142, 246,
            231, 189, 190, 13, 242, 219, 53, 77, 95, 185, 35, 153, 49, 49, 140, 120, 174, 222, 157,
            204, 173, 217, 115, 44, 227, 18, 211, 224, 46, 114, 159, 112, 116, 208, 215, 89, 216,
            4, 120, 89, 40, 22, 110, 223, 254, 76, 237, 99, 144, 174, 177, 112, 234, 65, 145, 185,
            115, 155, 251, 227, 247, 132, 185, 67, 70, 79, 238, 175, 10, 46, 110, 78, 81, 78, 191,
            226, 93, 55, 207, 2, 199, 19, 108, 92, 197, 106, 249, 32, 234, 225, 25, 79, 255, 152,
            168, 12, 177, 99, 29, 186, 114, 248, 13, 232, 144, 247, 83, 67, 103, 230, 33, 16, 67,
            13, 111, 130, 173, 139, 13, 72, 230, 231, 203, 86, 184, 6, 54, 27, 75, 145, 88, 229,
            167, 217, 165, 203, 238, 167, 47, 56, 58, 111, 49, 165, 235, 232, 170, 186, 73, 201,
            106, 59, 33, 120, 164, 229, 196, 194, 124, 165, 226, 197, 137, 73, 18, 93, 20, 166,
            218, 166, 173, 245, 241, 251, 229, 254, 245, 7, 24, 81, 180, 10, 141, 115, 9, 149, 120,
            120, 142, 4, 173, 215, 155, 222, 118, 153, 38, 149, 45, 148, 28, 120, 60, 198, 252, 61,
            103, 242, 3, 18, 195, 246
        ]
    )
}

#[test]
fn public_key_from_bytes() {
    let esk = SecretKey::hash(&SEED[..]);
    let epk = PublicKey::from(&esk);
    let apk = PublicKey::from_bytes(&[
        180, 38, 11, 239, 38, 13, 55, 164, 241, 71, 116, 212, 199, 63, 84, 180, 147, 139, 93, 230,
        92, 253, 51, 91, 148, 102, 103, 112, 252, 187, 0, 198, 76, 156, 221, 125, 188, 60, 106,
        240, 171, 134, 4, 43, 181, 132, 243, 86, 19, 131, 35, 193, 11, 141, 217, 90, 126, 18, 252,
        181, 92, 113, 11, 133, 62, 134, 83, 59, 40, 90, 149, 137, 10, 244, 142, 246, 231, 189, 190,
        13, 242, 219, 53, 77, 95, 185, 35, 153, 49, 49, 140, 120, 174, 222, 157, 204, 173, 217,
        115, 44, 227, 18, 211, 224, 46, 114, 159, 112, 116, 208, 215, 89, 216, 4, 120, 89, 40, 22,
        110, 223, 254, 76, 237, 99, 144, 174, 177, 112, 234, 65, 145, 185, 115, 155, 251, 227, 247,
        132, 185, 67, 70, 79, 238, 175, 10, 46, 110, 78, 81, 78, 191, 226, 93, 55, 207, 2, 199, 19,
        108, 92, 197, 106, 249, 32, 234, 225, 25, 79, 255, 152, 168, 12, 177, 99, 29, 186, 114,
        248, 13, 232, 144, 247, 83, 67, 103, 230, 33, 16, 67, 13, 111, 130, 173, 139, 13, 72, 230,
        231, 203, 86, 184, 6, 54, 27, 75, 145, 88, 229, 167, 217, 165, 203, 238, 167, 47, 56, 58,
        111, 49, 165, 235, 232, 170, 186, 73, 201, 106, 59, 33, 120, 164, 229, 196, 194, 124, 165,
        226, 197, 137, 73, 18, 93, 20, 166, 218, 166, 173, 245, 241, 251, 229, 254, 245, 7, 24, 81,
        180, 10, 141, 115, 9, 149, 120, 120, 142, 4, 173, 215, 155, 222, 118, 153, 38, 149, 45,
        148, 28, 120, 60, 198, 252, 61, 103, 242, 3, 18, 195, 246,
    ]);
    assert_eq!(apk.is_some().unwrap_u8(), 1);
    assert_eq!(epk, apk.unwrap());
}