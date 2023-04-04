/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
//! Oberon allows endpoints to issue multi-factor capable tokens to consumers
//! who can prove their validity with disclosing the tokens themselves without requiring
//! email, SMS, or authenticator apps. Endpoints
//! only need to store a single public key and not any tokens. An attacker that breaks
//! into the server doesn't have any password/token files to steal and only would see
//! a public key. The proof of token validity is only 96 bytes while the token itself
//! is only 48 bytes. The issuing party and verifying servers can be separate entities.
//!
//! Tokens are created by signing an identitifier with a secret key.
//!
//! Tokens are presented to a verifier as a zero-knowledge proof such that
//! the verifier never learns the value of the token. Additional blindings
//! can be applied to the token so additional security factors are required
//! before using it. One example is a pin or password.
//!
//! ```
//! use oberon::*;
//! use rand::thread_rng;
//!
//! let sk = SecretKey::hash(b"my super secret key seed");
//! let pk = PublicKey::from(&sk);
//! let id = b"test identity";
//! let token = sk.sign(id).unwrap();
//! let blinding = Blinding::new(b"<your passcode>");
//! let blinded_token = token - &blinding;
//!
//! let timestamp = [0x00, 0x05, 0xc0, 0xba, 0xea, 0x9c, 0x82, 0xb0];
//!
//! match Proof::new(&blinded_token, &[blinding], id, &timestamp, thread_rng()) {
//!     None => panic!(""),
//!     Some(proof) => {
//!         assert_eq!(proof.open(pk, id, &timestamp).unwrap_u8(), 1u8);
//!     }
//! }
//! ```
//!
//! This crate supports no-std by default. As such this means only 2 additional factors
//! can be used. This is usually not a problem since 3FA is good enough. If you need
//! more than 3FA (what security context are in???) this can be done with some work
//! as is described below.
//!
//! Blinding factors are applied to tokens as follows
//!
//! ```
//! use oberon::{SecretKey, Token, Blinding};
//!
//! let sk = SecretKey::hash(b"my super secret key seed");
//! let token = sk.sign(b"test identity").unwrap();
//!
//! let blinded_token = token - Blinding::new(b"<your pin number>");
//! let blinded_token = blinded_token - Blinding::new(b"<another factor like HSM key>");
//! let blinded_token = blinded_token - Blinding::new(b"<another factor like ENV>");
//! ```
//!
//! It is important that the blindings are subtracted and not added since addition is used
//! by `Proof::new`
//!
//! This scenario uses 3 extra blindings. In no-std mode, only two can be passed
//! to `Proof::new`. In order to apply the third and still have this work, you simply
//! reverse all but two of the blindings by adding them back in.
//! This restriction doesn't apply when `alloc` or `std` features are used.
//!
//! This crate also supports compiling to wasm. Make sure to use --features=wasm
//! to get the necessary functions

#![no_std]
#![deny(
    warnings,
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "wasm")]
macro_rules! wasm_slice_impl {
    ($name:ident) => {
        impl wasm_bindgen::describe::WasmDescribe for $name {
            fn describe() {
                wasm_bindgen::describe::inform(wasm_bindgen::describe::SLICE)
            }
        }

        impl wasm_bindgen::convert::IntoWasmAbi for $name {
            type Abi = wasm_bindgen::convert::WasmSlice;

            fn into_abi(self) -> Self::Abi {
                let a = self.to_bytes();
                Self::Abi {
                    ptr: a.as_ptr().into_abi(),
                    len: a.len() as u32,
                }
            }
        }

        impl wasm_bindgen::convert::FromWasmAbi for $name {
            type Abi = wasm_bindgen::convert::WasmSlice;

            #[inline]
            unsafe fn from_abi(js: Self::Abi) -> Self {
                use core::{convert::TryFrom, slice};

                let ptr = <*mut u8>::from_abi(js.ptr);
                let len = js.len as usize;
                let r = slice::from_raw_parts(ptr, len);

                match <[u8; $name::BYTES]>::try_from(r) {
                    Ok(d) => $name::from_bytes(&d).unwrap(),
                    Err(_) => Self::default(),
                }
            }
        }

        impl wasm_bindgen::convert::OptionIntoWasmAbi for $name {
            fn none() -> wasm_bindgen::convert::WasmSlice {
                wasm_bindgen::convert::WasmSlice { ptr: 0, len: 0 }
            }
        }

        impl wasm_bindgen::convert::OptionFromWasmAbi for $name {
            fn is_none(slice: &wasm_bindgen::convert::WasmSlice) -> bool {
                slice.ptr == 0
            }
        }

        impl TryFrom<wasm_bindgen::JsValue> for $name {
            type Error = &'static str;

            fn try_from(value: wasm_bindgen::JsValue) -> Result<Self, Self::Error> {
                serde_json::from_str::<$name>(&value.as_string().unwrap())
                    .map_err(|_| "unable to deserialize value")
            }
        }
    };
}

mod blinding;
#[cfg(feature = "ffi")]
mod ffi;
#[cfg(feature = "php")]
mod php;
mod proof;
mod public_key;
#[cfg(feature = "python")]
mod python;
mod secret_key;
mod token;
mod util;
#[cfg(feature = "wasm")]
mod web;

pub use blinding::*;
#[cfg_attr(docsrs, doc(cfg(feature = "ffi")))]
#[cfg(feature = "ffi")]
pub use ffi::*;
#[cfg_attr(docsrs, doc(cfg(feature = "php")))]
#[cfg(feature = "php")]
pub use php::*;
pub use proof::*;
pub use public_key::*;
#[cfg_attr(docsrs, doc(cfg(feature = "python")))]
#[cfg(feature = "python")]
pub use python::*;
pub use secret_key::*;
pub use token::*;
#[cfg_attr(docsrs, doc(cfg(feature = "wasm")))]
#[cfg(feature = "wasm")]
pub use web::*;
