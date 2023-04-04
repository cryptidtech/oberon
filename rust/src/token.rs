/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{util::*, Blinding, PublicKey, SecretKey};
use bls12_381_plus::{
    ff::Field,
    group::{Curve, Group},
};
use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar,
};
#[cfg(feature = "wasm")]
use core::convert::TryFrom;
use core::ops::{Add, Sub};
use serde::{Deserialize, Serialize};
use subtle::{Choice, ConstantTimeEq, CtOption};
use zeroize::ZeroizeOnDrop;

/// The authentication token
/// Display is not implemented to prevent accidental leak of the token
#[derive(Clone, Debug, Eq, Deserialize, Serialize, ZeroizeOnDrop)]
pub struct Token(pub(crate) G1Projective);

impl Default for Token {
    fn default() -> Self {
        Self(G1Projective::IDENTITY)
    }
}

impl PartialEq for Token {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).unwrap_u8() == 1
    }
}

impl ConstantTimeEq for Token {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(Token);

impl<'a, 'b> Add<&'b Blinding> for &'a Token {
    type Output = Token;

    #[inline]
    fn add(self, rhs: &'b Blinding) -> Token {
        self + *rhs
    }
}

impl<'b> Add<&'b Blinding> for Token {
    type Output = Token;

    #[inline]
    fn add(self, rhs: &'b Blinding) -> Token {
        self + *rhs
    }
}

impl<'a> Add<Blinding> for &'a Token {
    type Output = Token;

    #[inline]
    fn add(self, rhs: Blinding) -> Token {
        Token(self.0 + rhs.0)
    }
}

impl Add<Blinding> for Token {
    type Output = Token;

    #[inline]
    fn add(self, rhs: Blinding) -> Token {
        Token(self.0 + rhs.0)
    }
}

impl<'a, 'b> Sub<&'b Blinding> for &'a Token {
    type Output = Token;

    #[inline]
    fn sub(self, rhs: &'b Blinding) -> Token {
        self - *rhs
    }
}

impl<'b> Sub<&'b Blinding> for Token {
    type Output = Token;

    #[inline]
    fn sub(self, rhs: &'b Blinding) -> Token {
        self - *rhs
    }
}

impl<'a> Sub<Blinding> for &'a Token {
    type Output = Token;

    #[inline]
    fn sub(self, rhs: Blinding) -> Token {
        Token(self.0 - rhs.0)
    }
}

impl Sub<Blinding> for Token {
    type Output = Token;

    #[inline]
    fn sub(self, rhs: Blinding) -> Token {
        Token(self.0 - rhs.0)
    }
}

impl Token {
    /// The number of bytes in a token
    pub const BYTES: usize = 48;

    /// Create a new token
    pub fn new<B: AsRef<[u8]>>(sk: &SecretKey, id: B) -> Option<Self> {
        let id = id.as_ref();
        let m = hash_to_scalar(&[id]);
        if m.is_zero().unwrap_u8() == 1 {
            return None;
        }
        let m_tick = hash_to_scalar(&[&m.to_bytes()[..]]);
        if m_tick.is_zero().unwrap_u8() == 1 {
            return None;
        }
        let u = hash_to_curve(&m_tick.to_bytes()[..]);
        if u.is_identity().unwrap_u8() == 1 {
            return None;
        }

        let sigma = u * (sk.x + sk.w * m_tick + sk.y * m);
        if sigma.is_identity().unwrap_u8() == 1 {
            return None;
        }
        Some(Self(sigma))
    }

    /// Check whether the token is valid to the public key
    pub fn verify<B: AsRef<[u8]>>(&self, pk: PublicKey, id: B) -> Choice {
        let id = id.as_ref();
        let m = hash_to_scalar(&[id]);
        if m.is_zero().unwrap_u8() == 1 {
            return Choice::from(0u8);
        }
        let m_tick = hash_to_scalar(&[&m.to_bytes()[..]]);
        if m_tick.is_zero().unwrap_u8() == 1 {
            return Choice::from(0u8);
        }
        let u = hash_to_curve(&m_tick.to_bytes()[..]);
        if u.is_identity().unwrap_u8() == 1 {
            return Choice::from(0u8);
        }

        let rhs = G2Projective::sum_of_products_in_place(
            &[pk.w, pk.x, pk.y],
            &mut [m_tick, Scalar::ONE, m],
        );

        multi_miller_loop(&[
            (&u.to_affine(), &G2Prepared::from(rhs.to_affine())),
            (
                &self.0.to_affine(),
                &G2Prepared::from(-G2Affine::generator()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
    }

    /// Convert this token into a byte sequence
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Convert a bytes sequence into a token
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        G1Affine::from_compressed(data).map(|p| Self(G1Projective::from(p)))
    }
}
