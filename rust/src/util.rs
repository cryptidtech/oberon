/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::inner_types::{elliptic_curve::hash2curve::ExpandMsgXof, G1Projective, Scalar};
use digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

const TO_SCALAR_DST: &[u8] = b"OBERON_BLS12381FQ_XOF:SHAKE-256_";
const TO_CURVE_DST: &[u8] = b"OBERON_BLS12381G1_XOF:SHAKE-256_SSWU_RO_";

pub fn hash_to_scalar(data: &[&[u8]]) -> Scalar {
    let mut hasher = Shake256::default();
    hasher.update(TO_SCALAR_DST);
    for slice in data {
        hasher.update(slice);
    }
    let mut reader = hasher.finalize_xof();
    let mut data = [0u8; 48];
    reader.read(&mut data);
    Scalar::from_okm(&data)
}

pub fn hash_to_scalars(data: &[&[u8]], out: &mut [Scalar]) {
    let mut hasher = Shake256::default();
    hasher.update(TO_SCALAR_DST);
    for slice in data {
        hasher.update(slice);
    }
    let mut reader = hasher.finalize_xof();
    let mut data = [0u8; 48];
    for s in out {
        reader.read(&mut data);
        *s = Scalar::from_okm(&data);
    }
}

pub fn hash_to_curve(data: &[u8]) -> G1Projective {
    G1Projective::hash::<ExpandMsgXof<Shake256>>(data, TO_CURVE_DST)
}
