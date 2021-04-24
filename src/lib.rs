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
//! This crate supports no-std by default. As such this means only 2 additional factors
//! can be used. This is usually not a problem since 3FA is good enough. If you need
//! more than 3FA (what security context are in???) this can be done with some work
//! as is described later.

#![no_std]
#![deny(
    warnings,
    missing_docs,
    unused_import_braces,
    unused_qualifications,
    trivial_casts,
    trivial_numeric_casts
)]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
#[cfg_attr(feature = "wasm", macro_use)]
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
                value
                    .into_serde::<$name>()
                    .map_err(|_| "unable to deserialize value")
                // serde_wasm_bindgen::from_value(value).map_err(|_| "unable to deserialize value")
            }
        }
    };
}

mod blinding;
mod proof;
mod public_key;
mod secret_key;
mod token;
mod util;
#[cfg(feature = "wasm")]
mod web;

pub use blinding::*;
pub use proof::*;
pub use public_key::*;
pub use secret_key::*;
pub use token::*;
#[cfg(feature = "wasm")]
pub use web::*;
