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
}

impl Default for Proof {
    fn default() -> Self {
        Self {
            proof: G1Projective::identity(),
            u_tick: G1Projective::identity(),
        }
    }
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(Proof);

impl Proof {
    /// The number of bytes in a proof
    pub const BYTES: usize = 96;

    /// Create a new ZKP based proof
    pub fn new<B: AsRef<[u8]>, N: AsRef<[u8]>>(
        token: &Token,
        blindings: &[Blinding],
        id: B,
        nonce: N,
        rng: impl RngCore + CryptoRng,
    ) -> Option<Self> {
        #[cfg(not(any(feature = "alloc", feature = "std")))]
        {
            if blindings.len() > 2 {
                return None;
            }
        }

        let id = id.as_ref();
        let m = hash_to_scalar(&[id]);
        if m.is_zero() {
            return None;
        }
        let m_tick = hash_to_scalar(&[&m.to_bytes()[..]]);
        if m_tick.is_zero() {
            return None;
        }
        let u = hash_to_curve(&m_tick.to_bytes()[..]);
        if u.is_identity().unwrap_u8() == 1 {
            return None;
        }

        let t = hash_to_scalar(&[id, nonce.as_ref()]);
        let r = Scalar::random(rng);

        let u_tick = u * r;
        let (points, mut scalars) = get_points_and_scalars(&[u_tick, token.0], blindings, t, r);
        let proof = G1Projective::sum_of_products_in_place(&points, &mut scalars);
        Some(Self { proof, u_tick })
    }

    /// Check whether this proof is valid
    pub fn open<B: AsRef<[u8]>, N: AsRef<[u8]>>(&self, pk: PublicKey, id: B, nonce: N) -> Choice {
        if self.u_tick.is_identity().unwrap_u8() == 1 || self.proof.is_identity().unwrap_u8() == 1 {
            return Choice::from(0u8);
        }

        let id = id.as_ref();
        let m = hash_to_scalar(&[id]);
        if m.is_zero() {
            return Choice::from(0u8);
        }
        let m_tick = hash_to_scalar(&[&m.to_bytes()[..]]);
        if m_tick.is_zero() {
            return Choice::from(0u8);
        }

        let t = hash_to_scalar(&[id, nonce.as_ref()]);

        let rhs = G2Projective::sum_of_products_in_place(
            &[pk.w, pk.x, pk.y, G2Projective::generator()],
            &mut [m_tick, Scalar::one(), m, t],
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
        out.copy_from_slice(&self.proof.to_affine().to_compressed());
        out.copy_from_slice(&self.u_tick.to_affine().to_compressed());
        out
    }

    /// Convert a byte sequence to a proof
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        let pp = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[..48]).unwrap())
            .map(|p| G1Projective::from(p));
        let uu = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[48..]).unwrap())
            .map(|p| G1Projective::from(p));

        pp.and_then(|proof| {
            uu.and_then(|u_tick| CtOption::new(Self { proof, u_tick }, Choice::from(1u8)))
        })
    }
}

#[cfg(not(any(feature = "alloc", feature = "std")))]
/// Allows up to two blinding factors
fn get_points_and_scalars(
    initial: &[G1Projective; 2],
    blindings: &[Blinding],
    t: Scalar,
    r: Scalar,
) -> ([G1Projective; 4], [Scalar; 4]) {
    (
        [initial[0], initial[1], blindings[0].0, blindings[1].0],
        [t, r, r, r],
    )
}

#[cfg(any(feature = "alloc", feature = "std"))]
fn get_points_and_scalars(
    initial: &[G1Projective; 2],
    blindings: &[Blinding],
    t: Scalar,
    r: Scalar,
) -> (Vec<G1Projective>, Vec<Scalar>) {
    let mut points = Vec::with_capacity(2 + blindings.len());
    let mut scalars = Vec::with_capacity(2 + blindings.len());

    points.extend_from_slice(initial);
    scalars.push(t);
    scalars.push(r);

    for b in blindings {
        points.push(b.0);
        scalars.push(r);
    }
    (points, scalars)
}
