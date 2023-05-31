/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::inner_types::{group::Curve, G1Affine, G1Projective};
use crate::util::*;
#[cfg(feature = "wasm")]
use core::convert::TryFrom;
use serde::{Deserialize, Serialize};
use subtle::CtOption;

/// A blinding factor is applied to a token to enable
/// multi factor authentication
///
/// ```
/// use oberon::Blinding;
///
/// let blinding = Blinding::new(b"1234");
///
/// assert_ne!(blinding.to_bytes(), [0u8; Blinding::BYTES]);
/// ```
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct Blinding(pub(crate) G1Projective);

impl Default for Blinding {
    fn default() -> Self {
        Self(G1Projective::IDENTITY)
    }
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(Blinding);

impl Blinding {
    /// The number of bytes in a blinding factor
    pub const BYTES: usize = 48;

    /// Create a new blinding factor
    pub fn new(data: &[u8]) -> Self {
        Self(hash_to_curve(data))
    }

    /// Convert this blinding factor into a byte sequence
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        self.0.to_affine().to_compressed()
    }

    /// Convert a byte sequence to a blinding factor
    pub fn from_bytes(data: &[u8; 48]) -> CtOption<Self> {
        G1Affine::from_compressed(data).map(|p| Self(G1Projective::from(p)))
    }
}
