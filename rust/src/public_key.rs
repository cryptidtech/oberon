/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{SecretKey, Token};
use bls12_381_plus::{group::Curve, G2Affine, G2Projective};
use core::convert::TryFrom;
use serde::{Deserialize, Serialize};
use subtle::{Choice, CtOption};

/// The public key used for verifying tokens
#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct PublicKey {
    pub(crate) w: G2Projective,
    pub(crate) x: G2Projective,
    pub(crate) y: G2Projective,
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            w: G2Projective::IDENTITY,
            x: G2Projective::IDENTITY,
            y: G2Projective::IDENTITY,
        }
    }
}

impl From<&SecretKey> for PublicKey {
    fn from(sk: &SecretKey) -> Self {
        Self {
            w: G2Projective::GENERATOR * sk.w,
            x: G2Projective::GENERATOR * sk.x,
            y: G2Projective::GENERATOR * sk.y,
        }
    }
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(PublicKey);

impl PublicKey {
    /// The number of bytes in a public key
    pub const BYTES: usize = 288;

    /// Is this public key invalid
    pub fn is_invalid(&self) -> Choice {
        self.w.is_identity() | self.y.is_identity() | self.x.is_identity()
    }

    /// Convert this public key into a byte sequence
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0..96].copy_from_slice(&self.w.to_affine().to_compressed()[..]);
        out[96..192].copy_from_slice(&self.x.to_affine().to_compressed()[..]);
        out[192..288].copy_from_slice(&self.y.to_affine().to_compressed()[..]);
        out
    }

    /// Convert a byte sequence to a public key
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        let ww = G2Affine::from_compressed(&<[u8; 96]>::try_from(&data[..96]).unwrap())
            .map(G2Projective::from);
        let xx = G2Affine::from_compressed(&<[u8; 96]>::try_from(&data[96..192]).unwrap())
            .map(G2Projective::from);
        let yy = G2Affine::from_compressed(&<[u8; 96]>::try_from(&data[192..]).unwrap())
            .map(G2Projective::from);

        ww.and_then(|w| {
            xx.and_then(|x| yy.and_then(|y| CtOption::new(Self { w, x, y }, Choice::from(1u8))))
        })
    }

    /// Verify that a token is valid
    pub fn verify_token<B: AsRef<[u8]>>(&self, id: B, token: &Token) -> Choice {
        token.verify(*self, id)
    }
}
