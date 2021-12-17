/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{util::*, Token};
use bls12_381_plus::Scalar;
use core::convert::TryFrom;
use ff::Field;
use rand_core::*;
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq, CtOption};
use zeroize::Zeroize;

/// The secret key used for signing tokens
/// Display is not implemented to prevent accidental leak of the key
///
/// To generate a random secret key, select a random number generator
/// to pass to `new`
///
/// ```
/// use oberon::*;
/// let sk = SecretKey::new(rand::thread_rng());
/// ```
///
/// or to generate a secret key from a known seed
///
/// ```
/// use oberon::*;
/// let sk = SecretKey::hash(b"my seed");
/// ```
#[derive(Clone, Debug, Eq, Deserialize, Serialize, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    pub(crate) w: Scalar,
    pub(crate) x: Scalar,
    pub(crate) y: Scalar,
}

impl Default for SecretKey {
    fn default() -> Self {
        Self {
            w: Scalar::zero(),
            x: Scalar::zero(),
            y: Scalar::zero(),
        }
    }
}

impl From<&[u8; SecretKey::BYTES]> for SecretKey {
    fn from(data: &[u8; Self::BYTES]) -> Self {
        Self::from_bytes(data).unwrap()
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl ConstantTimeEq for SecretKey {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.x.ct_eq(&rhs.x) & self.y.ct_eq(&rhs.y) & self.w.ct_eq(&rhs.w)
    }
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(SecretKey);

impl SecretKey {
    /// The number of bytes in a secret key
    pub const BYTES: usize = 96;

    /// Generate a new random key
    pub fn new(mut rng: impl RngCore + CryptoRng) -> Self {
        Self {
            w: Scalar::random(&mut rng),
            x: Scalar::random(&mut rng),
            y: Scalar::random(&mut rng),
        }
    }

    /// Generate a new key from a seed using SHAKE-256
    pub fn hash(data: &[u8]) -> Self {
        let mut values = [Scalar::zero(); 3];
        hash_to_scalars(&[data], &mut values);
        Self {
            w: values[0],
            x: values[1],
            y: values[2],
        }
    }

    /// Convert this secret key into a byte sequence
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[..32].copy_from_slice(&self.w.to_bytes()[..]);
        out[32..64].copy_from_slice(&self.x.to_bytes()[..]);
        out[64..].copy_from_slice(&self.y.to_bytes()[..]);
        out
    }

    /// Convert a byte sequence to a secret key
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        let ww = Scalar::from_bytes(&<[u8; 32]>::try_from(&data[..32]).unwrap());
        let xx = Scalar::from_bytes(&<[u8; 32]>::try_from(&data[32..64]).unwrap());
        let yy = Scalar::from_bytes(&<[u8; 32]>::try_from(&data[64..]).unwrap());

        ww.and_then(|w| {
            xx.and_then(|x| yy.and_then(|y| CtOption::new(Self { w, x, y }, Choice::from(1u8))))
        })
    }

    /// Sign an `id` to a token
    pub fn sign<B: AsRef<[u8]>>(&self, id: B) -> Option<Token> {
        Token::new(self, id)
    }
}
