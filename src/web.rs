use crate::{Blinding, Proof, PublicKey, SecretKey, Token};
use rand::prelude::*;
use wasm_bindgen::prelude::*;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(any(feature = "alloc", feature = "std"))]
type BlindingList = Vec<Blinding>;
#[cfg(not(any(feature = "alloc", feature = "std")))]
type BlindingList = [Blinding; 4];

/// Create new random secret key
#[wasm_bindgen]
pub fn new_secret_key() -> SecretKey {
    let rng = thread_rng();
    SecretKey::new(rng)
}

/// Get the public key from the secret key
#[wasm_bindgen]
pub fn get_public_key(sk: SecretKey) -> PublicKey {
    PublicKey::from(&sk)
}

/// Create new secret key from a seed
#[wasm_bindgen]
pub fn secret_key_from_seed(seed: &[u8]) -> SecretKey {
    SecretKey::hash(seed)
}

/// Create a new token for a given ID
#[wasm_bindgen]
pub fn new_token(sk: SecretKey, id: &[u8]) -> Option<Token> {
    Token::new(&sk, id)
}

/// Verify a token for a given ID
#[wasm_bindgen]
pub fn verify_token(token: Token, pk: PublicKey, id: &[u8]) -> bool {
    token.verify(pk, id).unwrap_u8() == 1
}

/// Create a blinding factor from the specified data
#[wasm_bindgen]
pub fn create_blinding(data: &[u8]) -> Blinding {
    Blinding::new(data)
}

/// Adds a blinding factor to the token
#[wasm_bindgen]
pub fn add_blinding(token: Token, data: &[u8]) -> Token {
    token - Blinding::new(data)
}

/// Removes a blinding factor to the token
#[wasm_bindgen]
pub fn remove_blinding(token: Token, data: &[u8]) -> Token {
    token + Blinding::new(data)
}

/// Creates a proof using a nonce received from a verifier
#[wasm_bindgen]
pub fn create_proof(token: Token, id: &[u8], blindings: JsValue, nonce: &[u8]) -> Option<Proof> {
    let rng = thread_rng();
    match blindings.into_serde::<BlindingList>() {
        Err(_) => None,
        Ok(bs) => Proof::new(&token, &bs, id, nonce, rng),
    }
}

/// Creates a proof using a nonce received from a verifier
#[wasm_bindgen]
pub fn verify_proof(proof: Proof, pk: PublicKey, id: &[u8], nonce: &[u8]) -> bool {
    proof.open(pk, id, nonce).unwrap_u8() == 1
}
