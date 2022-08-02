#![allow(unused_doc_comments, missing_docs)]
use crate::{Blinding, Proof, PublicKey, SecretKey, Token};
use ffi_support::{
    define_bytebuffer_destructor, define_handle_map_deleter, define_string_destructor, ByteBuffer,
    ConcurrentHandleMap, ErrorCode, ExternError,
};
use lazy_static::lazy_static;
use std::prelude::v1::String;
use std::{ptr, slice, vec::Vec};

lazy_static! {
    /// The context manager for creating proofs
    pub static ref CREATE_PROOF_CONTEXT: ConcurrentHandleMap<CreateProofContext> =
        ConcurrentHandleMap::new();
}

/// Cleanup created strings
define_string_destructor!(oberon_string_free);
/// Cleanup created byte buffers
define_bytebuffer_destructor!(oberon_byte_buffer_free);
/// Cleanup created proof contexts
define_handle_map_deleter!(CREATE_PROOF_CONTEXT, oberon_create_proof_free);

/// The proof context object
pub struct CreateProofContext {
    /// The proof token
    pub token: Option<Token>,
    /// The token blindings
    pub blindings: Vec<Blinding>,
    /// The id associated with the token
    pub id: Option<Vec<u8>>,
    /// The proof nonce
    pub nonce: Option<Vec<u8>>,
}

/// Used for receiving byte arrays
#[repr(C)]
pub struct ByteArray {
    length: usize,
    data: *const u8,
}

impl Default for ByteArray {
    fn default() -> Self {
        Self {
            length: 0,
            data: ptr::null(),
        }
    }
}

impl From<&Vec<u8>> for ByteArray {
    fn from(b: &Vec<u8>) -> Self {
        Self::from_slice(b.as_slice())
    }
}

impl From<Vec<u8>> for ByteArray {
    fn from(b: Vec<u8>) -> Self {
        Self::from_slice(b.as_slice())
    }
}

impl From<ByteBuffer> for ByteArray {
    fn from(b: ByteBuffer) -> Self {
        Self::from_slice(&b.destroy_into_vec())
    }
}

impl ByteArray {
    /// Convert to a byte vector
    pub fn to_vec(&self) -> Vec<u8> {
        if self.data.is_null() || self.length == 0 {
            Vec::new()
        } else {
            unsafe { slice::from_raw_parts(self.data, self.length).to_vec() }
        }
    }

    /// Convert to a byte vector if possible
    /// Some if success
    /// None if failure
    pub fn to_opt_vec(&self) -> Option<Vec<u8>> {
        if self.data.is_null() {
            None
        } else if self.length == 0 {
            Some(Vec::new())
        } else {
            Some(unsafe { slice::from_raw_parts(self.data, self.length).to_vec() })
        }
    }

    /// Convert to outgoing ByteBuffer
    pub fn into_byte_buffer(self) -> ByteBuffer {
        ByteBuffer::from_vec(self.to_vec())
    }

    /// Convert from a slice
    pub fn from_slice<I: AsRef<[u8]>>(data: I) -> Self {
        let data = data.as_ref();
        Self {
            length: data.len(),
            data: data.as_ptr(),
        }
    }
}

macro_rules! from_bytes {
    ($name:ident, $type:ident) => {
        fn $name(input: Vec<u8>) -> Option<$type> {
            match <[u8; $type::BYTES]>::try_from(input.as_slice()) {
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

/// The size of the secret key
#[no_mangle]
pub extern "C" fn oberon_secret_key_size() -> i32 {
    SecretKey::BYTES as i32
}

/// The size of the public key
#[no_mangle]
pub extern "C" fn oberon_public_key_size() -> i32 {
    PublicKey::BYTES as i32
}

/// The size of the token
#[no_mangle]
pub extern "C" fn oberon_token_size() -> i32 {
    Token::BYTES as i32
}

/// The size of a blinding
#[no_mangle]
pub extern "C" fn oberon_blinding_size() -> i32 {
    Blinding::BYTES as i32
}

/// The size of a proof
#[no_mangle]
pub extern "C" fn oberon_proof_size() -> i32 {
    Proof::BYTES as i32
}

/// Create new random secret key
#[no_mangle]
pub extern "C" fn oberon_new_secret_key(secret_key: &mut ByteBuffer) -> i32 {
    let sk = SecretKey::new(rand::thread_rng());
    *secret_key = ByteBuffer::from_vec(sk.to_bytes().to_vec());
    0
}

/// Get the public key from the secret key
#[no_mangle]
pub extern "C" fn oberon_get_public_key(
    sk: ByteArray,
    public_key: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let t = sk.to_vec();
    match secret_key(t) {
        None => {
            *err = ExternError::new_error(ErrorCode::new(1), String::from("Invalid secret key"));
            1
        }
        Some(sk) => {
            let pk = PublicKey::from(&sk);
            *public_key = ByteBuffer::from_vec(pk.to_bytes().to_vec());
            0
        }
    }
}

/// Create new secret key from a seed
#[no_mangle]
pub extern "C" fn oberon_secret_key_from_seed(seed: ByteArray, sk: &mut ByteBuffer) -> i32 {
    let t = SecretKey::hash(seed.to_vec().as_slice());
    *sk = ByteBuffer::from_vec(t.to_bytes().to_vec());
    0
}

/// Create a new token for a given ID
#[no_mangle]
pub extern "C" fn oberon_new_token(
    sk: ByteArray,
    id: ByteArray,
    token: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let t = sk.to_vec();
    match secret_key(t) {
        None => {
            *err = ExternError::new_error(ErrorCode::new(1), String::from("Invalid secret key"));
            1
        }
        Some(sk) => match Token::new(&sk, id.to_vec()) {
            None => {
                *err = ExternError::new_error(
                    ErrorCode::new(2),
                    String::from("Unable to create token"),
                );
                2
            }
            Some(tk) => {
                *token = ByteBuffer::from_vec(tk.to_bytes().to_vec());
                0
            }
        },
    }
}

/// Verify a token for a given ID
#[no_mangle]
pub extern "C" fn oberon_verify_token(
    token: ByteArray,
    pk: ByteArray,
    id: ByteArray,
    err: &mut ExternError,
) -> i32 {
    match (get_token(token.to_vec()), public_key(pk.to_vec())) {
        (Some(tk), Some(pk)) => {
            let res = tk.verify(pk, id.to_vec()).unwrap_u8() as i32;
            -(res - 1)
        }
        (_, _) => {
            *err = ExternError::new_error(
                ErrorCode::new(1),
                String::from("Invalid token and/or public key"),
            );
            1
        }
    }
}

/// Create a blinding factor from the specified data
#[no_mangle]
pub extern "C" fn oberon_create_blinding(data: ByteArray, blinding: &mut ByteBuffer) -> i32 {
    *blinding = ByteBuffer::from_vec(Blinding::new(data.to_vec().as_slice()).to_bytes().to_vec());
    0
}

/// Adds a blinding factor to the token
#[no_mangle]
pub extern "C" fn oberon_add_blinding(
    old_token: ByteArray,
    data: ByteArray,
    new_token: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    match get_token(old_token.to_vec()) {
        None => {
            *err = ExternError::new_error(ErrorCode::new(1), String::from("Invalid token"));
            1
        }
        Some(tk) => {
            let b = Blinding::new(data.to_vec().as_slice());
            let new_tk = tk - b;
            *new_token = ByteBuffer::from_vec(new_tk.to_bytes().to_vec());
            0
        }
    }
}

/// Removes a blinding factor to the token
#[no_mangle]
pub extern "C" fn oberon_remove_blinding(
    old_token: ByteArray,
    data: ByteArray,
    new_token: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    match get_token(old_token.to_vec()) {
        None => {
            *err = ExternError::new_error(ErrorCode::new(1), String::from("Invalid token"));
            1
        }
        Some(tk) => {
            let b = Blinding::new(data.to_vec().as_slice());
            let new_tk = tk + b;
            *new_token = ByteBuffer::from_vec(new_tk.to_bytes().to_vec());
            0
        }
    }
}

/// Creates a proof context
#[no_mangle]
pub extern "C" fn oberon_create_proof_init(err: &mut ExternError) -> u64 {
    CREATE_PROOF_CONTEXT.insert_with_output(err, || CreateProofContext {
        token: None,
        id: None,
        blindings: Vec::new(),
        nonce: None,
    })
}

/// Set the proof token
#[no_mangle]
pub extern "C" fn oberon_create_proof_set_token(
    handle: u64,
    token: ByteArray,
    err: &mut ExternError,
) -> i32 {
    CREATE_PROOF_CONTEXT.call_with_result_mut(err, handle, move |ctx| -> Result<(), ExternError> {
        match get_token(token.to_vec()) {
            None => Err(ExternError::new_error(
                ErrorCode::new(1),
                String::from("Invalid token"),
            )),
            Some(tk) => {
                ctx.token = Some(tk);
                Ok(())
            }
        }
    });
    err.get_code().code()
}

/// Set the proof id
#[no_mangle]
pub extern "C" fn oberon_create_proof_set_id(
    handle: u64,
    id: ByteArray,
    err: &mut ExternError,
) -> i32 {
    CREATE_PROOF_CONTEXT.call_with_output_mut(err, handle, move |ctx| {
        ctx.id = Some(id.to_vec());
    });
    err.get_code().code()
}

/// Set the proof nonce
#[no_mangle]
pub extern "C" fn oberon_create_proof_set_nonce(
    handle: u64,
    nonce: ByteArray,
    err: &mut ExternError,
) -> i32 {
    CREATE_PROOF_CONTEXT.call_with_output_mut(err, handle, move |ctx| {
        ctx.nonce = Some(nonce.to_vec());
    });
    err.get_code().code()
}

/// Set the proof blinding
#[no_mangle]
pub extern "C" fn oberon_create_proof_add_blinding(
    handle: u64,
    blinding: ByteArray,
    err: &mut ExternError,
) -> i32 {
    CREATE_PROOF_CONTEXT.call_with_output_mut(err, handle, move |ctx| {
        ctx.blindings
            .push(Blinding::new(blinding.to_vec().as_slice()));
    });
    err.get_code().code()
}

/// Create the proof
#[no_mangle]
pub extern "C" fn oberon_create_proof_finish(
    handle: u64,
    proof: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let pf = CREATE_PROOF_CONTEXT.call_with_result(
        err,
        handle,
        move |ctx| -> Result<ByteBuffer, ExternError> {
            if ctx.id.is_none() {
                return Err(ExternError::new_error(
                    ErrorCode::new(1),
                    String::from("Id must be set"),
                ));
            }
            if ctx.nonce.is_none() {
                return Err(ExternError::new_error(
                    ErrorCode::new(2),
                    String::from("Nonce must be set"),
                ));
            }
            if ctx.token.is_none() {
                return Err(ExternError::new_error(
                    ErrorCode::new(3),
                    String::from("Token must be set"),
                ));
            }
            match (ctx.id.as_ref(), ctx.nonce.as_ref(), ctx.token.as_ref()) {
                (Some(id), Some(nonce), Some(token)) => {
                    match Proof::new(
                        token,
                        ctx.blindings.as_slice(),
                        id,
                        nonce,
                        rand::thread_rng(),
                    ) {
                        None => Err(ExternError::new_error(
                            ErrorCode::new(4),
                            String::from("Invalid proof parameters"),
                        )),
                        Some(p) => Ok(ByteBuffer::from_vec(p.to_bytes().to_vec())),
                    }
                }
                (_, _, _) => Err(ExternError::new_error(
                    ErrorCode::new(5),
                    String::from("Invalid parameters"),
                )),
            }
        },
    );
    if err.get_code().is_success() {
        *proof = pf;
        if let Err(e) = CREATE_PROOF_CONTEXT.remove_u64(handle) {
            *err = ExternError::new_error(ErrorCode::new(6), std::format!("{:?}", e))
        }
    }
    err.get_code().code()
}

/// Creates a proof using a nonce received from a verifier
#[no_mangle]
pub extern "C" fn oberon_verify_proof(
    proof: ByteArray,
    pk: ByteArray,
    id: ByteArray,
    nonce: ByteArray,
    err: &mut ExternError,
) -> i32 {
    match (get_proof(proof.to_vec()), public_key(pk.to_vec())) {
        (Some(pf), Some(pub_key)) => {
            let res = pf
                .open(pub_key, id.to_vec().as_slice(), nonce.to_vec().as_slice())
                .unwrap_u8() as i32;
            -(res - 1)
        }
        (_, _) => {
            *err = ExternError::new_error(
                ErrorCode::new(1),
                String::from("Invalid proof and/or public key"),
            );
            1
        }
    }
}
