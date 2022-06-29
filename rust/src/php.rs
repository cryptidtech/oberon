/*
    Copyright Michael Lodder. All Rights Reserved.
    SPDX-License-Identifier: Apache-2.0
*/
use crate::{Blinding, Proof, PublicKey, SecretKey, Token};
use rand::prelude::*;
#[cfg_attr(windows, feature(abi_vectorcall))]
use ext_php_rs::prelude::*;

use std::{
    convert::TryFrom,
    vec::Vec
};
use ext_php_rs::{info_table_end, info_table_row, info_table_start};
use ext_php_rs::zend::ModuleEntry;

/// Create a new secret key
#[php_function]
pub fn new_secret_key() -> Vec<u8> {
    let rng = thread_rng();
    SecretKey::new(rng).to_bytes().to_vec()
}

/// Get the public key from the secret key
#[php_function]
pub fn get_public_key(sk: Vec<u8>) -> Option<Vec<u8>> {
    match secret_key(sk) {
        None => None,
        Some(sk) => {
            Some(PublicKey::from(&sk).to_bytes().to_vec())
        }
    }
}

/// Create new secret key from a seed
#[php_function]
pub fn secret_key_from_seed(seed: Vec<u8>) -> Vec<u8> {
    SecretKey::hash(&seed).to_bytes().to_vec()
}

/// Create a new token for a given ID
#[php_function]
pub fn new_token(sk: Vec<u8>, id: Vec<u8>) -> Option<Vec<u8>> {
    match secret_key(sk) {
        None => None,
        Some(sk) => {
            Some(Token::new(&sk.unwrap(), &id).unwrap().to_bytes().to_vec())
        }
    }
}

/// Verify a token for a given ID
#[php_function]
pub fn verify_token(token: Vec<u8>, pk: Vec<u8>, id: Vec<u8>) -> bool {
    match (get_token(token), public_key(pk)) {
        (Some(t), Some(k)) => {
            t.verify(k, &id).unwrap_u8() == 1
        },
        (_, _) => false
    }
}

/// Create a blinding factor from the specified data
#[php_function]
pub fn create_blinding(data: Vec<u8>) -> Vec<u8>{
    Blinding::new(&data).to_bytes().to_vec()
}

/// Adds a blinding factor to the token
#[php_function]
pub fn add_blinding(token: Vec<u8>, data: Vec<u8>) -> Option<Vec<u8>> {
    match get_token(token) {
        None => None,
        Some(t) => {
            let val = t - Blinding::new(&data);
            Some(val.to_bytes().to_vec())
        }
    }
}

/// Removes a blinding factor to the token
#[php_function]
pub fn remove_blinding(token: Vec<u8>, data: Vec<u8>) -> Option<Vec<u8>> {
    match get_token(token) {
        None => None,
        Some(t) => {
            let val = t + Blinding::new(&data);
            Some(val.to_bytes().to_vec())
        }
    }
}

/// Creates a proof using a nonce received from a verifier
#[php_function]
pub fn create_proof(token: Vec<u8>, id: Vec<u8>, blindings: Vec<Vec<u8>>, nonce: Vec<u8>) -> Option<Vec<u8>> {
    let bs: Vec<Blinding> = blindings.iter().map(|b| Blinding::new(b)).collect();

    let rng = thread_rng();
    match get_token(token) {
        None => None,
        Some(t) => {
            Proof::new(&t, &bs, id, nonce, rng).map(|p| p.to_bytes().to_vec())
        }
    }
}

/// Creates a proof using a nonce received from a verifier
#[php_function]
pub fn verify_proof(proof: Vec<u8>, pk: Vec<u8>, id: Vec<u8>, nonce: Vec<u8>) -> bool {
    match (get_proof(proof), public_key(pk)) {
        (Some(p), Some(k)) => {
            p.open(k, id, nonce).unwrap_u8() == 1
        },
        (_, _) => false
    }

}

macro_rules! from_bytes {
    ($name:ident, $type:ident) => {
        fn $name(input: Vec<u8>) -> Option<$type> {
            match <[u8; $type::BYTES]>::try_from(&input) {
                Err(_) => None,
                Ok(bytes) => {
                    let val = $type::from_bytes(&bytes);
                    if val.is_some().unwrap_u8() == 1u8 {
                        Some(val.unwrap())
                    } else {
                        None
                    }
                }
            }
        }
    };
}

from_bytes!(secret_key, SecretKey);
from_bytes!(public_key, PublicKey);
from_bytes!(get_token, Token);
from_bytes!(get_proof, Proof);

#[no_mangle]
pub extern "C" fn php_module_info(_module: *mut ModuleEntry) {
    info_table_start!();
    info_table_row!("oberon extension", "enabled");
    info_table_end!();
}

#[php_module]
pub fn module(module: ModuleBuilder) -> ModuleBuilder {
    module.info_function(php_module_info)
}