/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::inner_types::*;
use crate::{util::*, Blinding, PublicKey, Token};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use subtle::{Choice, CtOption};

/// A zero-knowledge proof of a valid token
#[derive(Copy, Clone, Debug, Default, Deserialize, Serialize)]
pub struct Proof {
    u: G1Projective,
    z: G1Projective,
}

#[cfg(feature = "wasm")]
wasm_slice_impl!(Proof);

impl Proof {
    /// The number of bytes in a proof
    pub const BYTES: usize = 96;

    /// Create a new ZKP based proof
    ///
    /// Works like this
    ///
    /// m  = H_s(id)
    /// m' = H_s(m)
    /// A  = H_G(m')
    /// r = random scalar
    /// t = random scalar or H_s(A || timestamp)
    /// U = r.A
    /// Z = -(r + t).(\sigma + blindings)
    ///
    /// Verified
    /// e(U + t.A, W + m.X + m'.Y).e(Z, P) == 1
    pub fn new<B: AsRef<[u8]>, N: AsRef<[u8]>>(
        token: &Token,
        blindings: &[Blinding],
        id: B,
        nonce: N,
        mut rng: impl RngCore + CryptoRng,
    ) -> Option<Self> {
        let id = id.as_ref();
        let m = hash_to_scalar(&[id]);
        if m.is_zero().unwrap_u8() == 1 {
            return None;
        }
        let m_tick = hash_to_scalar(&[&m.to_le_bytes()[..]]);
        if m_tick.is_zero().unwrap_u8() == 1 {
            return None;
        }
        let a = hash_to_curve(&m_tick.to_le_bytes()[..]);
        if a.is_identity().unwrap_u8() == 1 {
            return None;
        }

        let r = gen_nonz_rnd_scalar(&mut rng);
        let u = a * r;
        let t = hash_to_scalar(&[&u.to_affine().to_compressed(), nonce.as_ref()]);

        let z: G1Projective =
            (token.0 + blindings.iter().map(|b| b.0).sum::<G1Projective>()) * (r + t);
        Some(Self { u, z: -z })
    }

    /// Check whether this proof is valid
    pub fn open<B: AsRef<[u8]>, N: AsRef<[u8]>>(&self, pk: PublicKey, id: B, nonce: N) -> Choice {
        if (self.u.is_identity() | self.z.is_identity() | pk.is_invalid()).unwrap_u8() == 1u8 {
            return 0u8.into();
        }

        let id = id.as_ref();
        let m = hash_to_scalar(&[id]);
        if m.is_zero().unwrap_u8() == 1 {
            return 0u8.into();
        }
        let m_tick = hash_to_scalar(&[&m.to_le_bytes()[..]]);
        if m_tick.is_zero().unwrap_u8() == 1u8 {
            return 0u8.into();
        }
        let a = hash_to_curve(&m_tick.to_le_bytes()[..]);
        if a.is_identity().unwrap_u8() == 1 {
            return 0u8.into();
        }

        let t = hash_to_scalar(&[&self.u.to_affine().to_compressed(), nonce.as_ref()]);

        let u = a * t + self.u;
        #[cfg(feature = "std")]
        let rhs = G2Projective::sum_of_products(
            &[pk.w, pk.x, pk.y],
            &[m_tick, Scalar::ONE, m],
        );
        #[cfg(all(feature = "rust", not(feature = "std")))]
        let rhs = G2Projective::sum_of_products_in_place(
            &[pk.w, pk.x, pk.y],
            &mut [m_tick, Scalar::ONE, m],
        );

        multi_miller_loop(&[
            (&u.to_affine(), &G2Prepared::from(rhs.to_affine())),
            (
                &self.z.to_affine(),
                &G2Prepared::from(G2Affine::generator()),
            ),
        ])
        .final_exponentiation()
        .is_identity()
    }

    /// Convert this proof into a byte sequence
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[..48].copy_from_slice(&self.u.to_affine().to_compressed());
        out[48..].copy_from_slice(&self.z.to_affine().to_compressed());
        out
    }

    /// Convert a byte sequence to a proof
    pub fn from_bytes(data: &[u8; Self::BYTES]) -> CtOption<Self> {
        let uu = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[..48]).unwrap())
            .map(G1Projective::from);
        let zz = G1Affine::from_compressed(&<[u8; 48]>::try_from(&data[48..]).unwrap())
            .map(G1Projective::from);

        uu.and_then(|u| zz.and_then(|z| CtOption::new(Proof { u, z }, 1u8.into())))
    }
}

fn gen_nonz_rnd_scalar(mut rng: impl RngCore + CryptoRng) -> Scalar {
    let mut s = Scalar::random(&mut rng);
    while s.is_zero().unwrap_u8() == 1 || s == Scalar::ONE {
        s = Scalar::random(&mut rng);
    }
    s
}

#[test]
fn eproof_works() {
    let sk = crate::SecretKey::new(rand::thread_rng());
    let pk = PublicKey::from(&sk);
    let id = b"eproof_works";
    let token = sk.sign(id).unwrap();

    let blinding = Blinding::new(b"1234");
    let blind_token = token.clone() - blinding;

    let nonce = b"eproof_works_nonce";

    let opt_eproof = Proof::new(&token, &[], id, nonce, rand::thread_rng());
    assert!(opt_eproof.is_some());
    let mut eproof = opt_eproof.unwrap();
    assert_eq!(eproof.open(pk, id, nonce).unwrap_u8(), 1u8);

    let t = Scalar::random(rand::thread_rng());
    eproof.u *= t;
    eproof.z *= t;
    assert_eq!(eproof.open(pk, id, nonce).unwrap_u8(), 0u8);

    let opt_eproof = Proof::new(&blind_token, &[blinding], id, nonce, rand::thread_rng());
    assert!(opt_eproof.is_some());
    let mut eproof = opt_eproof.unwrap();
    assert_eq!(eproof.open(pk, id, nonce).unwrap_u8(), 1u8);

    let t = Scalar::random(rand::thread_rng());
    eproof.u *= t;
    eproof.z *= t;
    assert_eq!(eproof.open(pk, id, nonce).unwrap_u8(), 0u8);
}
