/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{util::*, Blinding, PublicKey, Token};
use bls12_381_plus::{
    multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Scalar,
};
use core::convert::TryFrom;
use ff::Field;
use group::Group;
use rand_core::*;
use serde::{Deserialize, Serialize};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
use group::Curve;
#[cfg(feature = "std")]
use std::vec::Vec;
use subtle::{Choice, CtOption};

/// A zero-knowledge proof of a valid token
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct Proof {
    proof: G1Projective,
    u_tick: G1Projective,
    commitment: G2Projective,
    challenge: Scalar,
    schnorr: Scalar,
}

impl Default for Proof {
    fn default() -> Self {
        Self {
            proof: G1Projective::IDENTITY,
            u_tick: G1Projective::IDENTITY,
            commitment: G2Projective::IDENTITY,
            challenge: Scalar::ZERO,
            schnorr: Scalar::ZERO,
        }
    }
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(Proof);

impl Proof {
    /// The number of bytes in a proof
    pub const BYTES: usize = 256;

    /// Create a new ZKP based proof
    pub fn new<B: AsRef<[u8]>, N: AsRef<[u8]>>(
        token: &Token,
        blindings: &[Blinding],
        id: B,
        nonce: N,
        mut rng: impl RngCore + CryptoRng,
    ) -> Option<Self> {
        #[cfg(not(any(feature = "alloc", feature = "std")))]
        {
            if blindings.len() > MAX_BLINDING_FACTORS {
                return None;
            }
        }

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

        let t = gen_rnd_scalar(&mut rng);
        let tt = gen_rnd_scalar(&mut rng);
        let r = gen_rnd_scalar(&mut rng);

        let commitment = G2Projective::GENERATOR * t;
        let proving = G2Projective::GENERATOR * tt;
        let u_tick = u * r;
        let (points, mut scalars, len) =
            get_points_and_scalars(&[u_tick, token.0], blindings, t, r);
        let proof = G1Projective::sum_of_products_in_place(&points[..len], &mut scalars[..len]);
        let challenge = hash_to_scalar(&[
            id,
            &u_tick.to_affine().to_compressed(),
            &proof.to_affine().to_compressed(),
            &commitment.to_affine().to_compressed(),
            &proving.to_affine().to_compressed(),
            nonce.as_ref(),
        ]);
        let schnorr = tt - challenge * t;

        Some(Self {
            proof,
            u_tick,
            commitment,
            challenge,
            schnorr,
        })
    }

    /// Check whether this proof is valid
    pub fn open<B: AsRef<[u8]>, N: AsRef<[u8]>>(&self, pk: PublicKey, id: B, nonce: N) -> Choice {
        if self.u_tick.is_identity().unwrap_u8() == 1
            || self.proof.is_identity().unwrap_u8() == 1
            || self.commitment.is_identity().unwrap_u8() == 1
            || self.challenge.is_zero().unwrap_u8() == 1
            || self.schnorr.is_zero().unwrap_u8() == 1
        {
            return Choice::from(0u8);
        }

        let id = id.as_ref();
        let m = hash_to_scalar(&[id]);
        if m.is_zero().unwrap_u8() == 1 {
            return Choice::from(0u8);
        }
        let m_tick = hash_to_scalar(&[&m.to_bytes()[..]]);
        if m_tick.is_zero().unwrap_u8() == 1u8 {
            return Choice::from(0u8);
        }
        let s = self.schnorr;
        let c = self.challenge;

        let proving = G2Projective::sum_of_products_in_place(
            &[G2Projective::GENERATOR, self.commitment],
            &mut [s, c],
        );

        let challenge = hash_to_scalar(&[
            id,
            &self.u_tick.to_affine().to_compressed(),
            &self.proof.to_affine().to_compressed(),
            &self.commitment.to_affine().to_compressed(),
            &proving.to_affine().to_compressed(),
            nonce.as_ref(),
        ]);

        if challenge != self.challenge {
            return Choice::from(0u8);
        }

        let rhs = G2Projective::sum_of_products_in_place(
            &[pk.w, pk.x, pk.y, self.commitment],
            &mut [m_tick, Scalar::ONE, m, Scalar::ONE],
        );

        multi_miller_loop(&[
            (&self.u_tick.to_affine(), &G2Prepared::from(rhs.to_affine())),
            (
                &self.proof.to_affine(),
                &G2Prepared::from(-G2Affine::generator()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
    }

    /// Convert this proof into a byte sequence
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[..48].copy_from_slice(&self.proof.to_affine().to_compressed());
        out[48..96].copy_from_slice(&self.u_tick.to_affine().to_compressed());
        out[96..192].copy_from_slice(&self.commitment.to_affine().to_compressed());
        out[192..224].copy_from_slice(&self.challenge.to_bytes());
        out[224..].copy_from_slice(&self.schnorr.to_bytes());
        out
    }

    /// Convert a byte sequence to a proof
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        let pp = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[..48]).unwrap())
            .map(G1Projective::from);
        let uu = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[48..96]).unwrap())
            .map(G1Projective::from);
        let commit = G2Affine::from_compressed(&<[u8; 96]>::try_from(&data[96..192]).unwrap())
            .map(G2Projective::from);
        let chal = Scalar::from_bytes(&<[u8; 32]>::try_from(&data[192..224]).unwrap());
        let schn = Scalar::from_bytes(&<[u8; 32]>::try_from(&data[224..]).unwrap());

        pp.and_then(|proof| {
            uu.and_then(|u_tick| {
                commit.and_then(|commitment| {
                    chal.and_then(|challenge| {
                        schn.and_then(|schnorr| {
                            let is_some: u8 = ((challenge.is_zero() | schnorr.is_zero()).unwrap_u8() == 0).into();
                            CtOption::new(
                                Self {
                                    proof,
                                    u_tick,
                                    commitment,
                                    challenge,
                                    schnorr,
                                },
                                is_some.into(),
                            )
                        })
                    })
                })
            })
        })
    }
}

fn gen_rnd_scalar(mut rng: impl RngCore + CryptoRng) -> Scalar {
    let mut s = Scalar::random(&mut rng);
    while s.is_zero().unwrap_u8() == 1 || s == Scalar::ONE {
        s = Scalar::random(&mut rng);
    }
    s
}

#[cfg(not(any(feature = "alloc", feature = "std")))]
/// Allows up to two blinding factors
fn get_points_and_scalars(
    initial: &[G1Projective; 2],
    blindings: &[Blinding],
    t: Scalar,
    r: Scalar,
) -> ([G1Projective; 4], [Scalar; 4], usize) {
    let mut points = [
        initial[0],
        initial[1],
        G1Projective::IDENTITY,
        G1Projective::IDENTITY,
    ];
    for i in 0..blindings.len() {
        points[i + 2] = blindings[i].0
    }
    (points, [t, r, r, r], 2 + blindings.len())
}

#[cfg(any(feature = "alloc", feature = "std"))]
fn get_points_and_scalars(
    initial: &[G1Projective; 2],
    blindings: &[Blinding],
    t: Scalar,
    r: Scalar,
) -> (Vec<G1Projective>, Vec<Scalar>, usize) {
    let mut points = Vec::with_capacity(2 + blindings.len());
    let mut scalars = Vec::with_capacity(2 + blindings.len());

    points.extend_from_slice(initial);
    scalars.push(t);
    scalars.push(r);

    for b in blindings {
        points.push(b.0);
        scalars.push(r);
    }
    let l = points.len();
    (points, scalars, l)
}

#[test]
fn vectors() {}
