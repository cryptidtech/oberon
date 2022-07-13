use neon::{
    prelude::*,
    types::buffer::TypedArray,
};
use oberon::*;

macro_rules! slice_to_js_array_buffer {
    ($slice:expr, $cx:expr) => {{
        let mut result = JsArrayBuffer::new(&mut $cx, $slice.len())?;
        result.as_mut_slice(&mut $cx).copy_from_slice($slice);
        result
    }};
}

macro_rules! obj_field_to_vec {
    ($cx:expr, $field: expr) => {{
        let v: Vec<Handle<JsValue>> = $cx
            .argument::<JsArray>($field)?
            .to_vec(&mut $cx)?;
        v
    }};
}


/// @returns ArrayBuffer secret key
fn new_secret_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let sk = SecretKey::new(rand::thread_rng());
    Ok(slice_to_js_array_buffer!(&sk.to_bytes(), cx))
}


/// @param ArrayBuffer secret key
/// @returns ArrayBuffer public key
fn get_public_key(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let ja = JsArrayBuffer::new(&mut cx, 0)?;
    let secret_key_handle: Handle<JsArrayBuffer> = cx.argument(0)?;
    let secret_key_data = secret_key_handle.as_slice(&cx);
    if secret_key_data.len() != SecretKey::BYTES {
        return cx.throw(ja);
    }
    let secret_key_bytes = <[u8; SecretKey::BYTES]>::try_from(secret_key_data).unwrap();
    let ct_sk = SecretKey::from_bytes(&secret_key_bytes);
    if ct_sk.is_some().unwrap_u8() == 1u8 {
        let sk = ct_sk.unwrap();
        let pk = PublicKey::from(&sk);
        Ok(slice_to_js_array_buffer!(&pk.to_bytes(), cx))
    } else {
        cx.throw(ja)
    }
}


/// @param ArrayBuffer `seed` - seed data
/// @returns ArrayBuffer `secret key` - the secret key
fn secret_key_from_seed(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let seed_handle: Handle<JsArrayBuffer> = cx.argument(0)?;
    let seed_data = seed_handle.as_slice(&cx);
    let sk = SecretKey::hash(seed_data);
    Ok(slice_to_js_array_buffer!(&sk.to_bytes(), cx))
}


/// @param ArrayBuffer `id` - The identifier to use for this token
/// @param ArrayBuffer `secretKey` - The secret key used for signing this token
/// @returns ArrayBuffer `token` - The token
fn new_token(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let ja = JsArrayBuffer::new(&mut cx, 0)?;
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;
    let sk_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;

    let id_bytes = id_buffer.as_slice(&cx);
    let sk_bytes = sk_buffer.as_slice(&cx);

    if sk_bytes.len() != SecretKey::BYTES {
        return cx.throw(ja);
    }

    let sk = SecretKey::from_bytes(&<[u8; SecretKey::BYTES]>::try_from(sk_bytes).unwrap()).unwrap();
    match Token::new(&sk, id_bytes) {
        None => cx.throw(ja),
        Some(token) => Ok(slice_to_js_array_buffer!(&token.to_bytes(), cx)),
    }
}


/// @param ArrayBuffer `token` - The token
/// @param ArrayBuffer `publicKey` - The public key used for verifying this token
/// @param ArrayBuffer `id` - The identifier to use for this token
/// @returns bool - True if valid, false otherwise
fn verify_token(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let res = JsBoolean::new(&mut cx, false);
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(2)?;
    let pk_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let tk_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;

    let id_bytes = id_buffer.as_slice(&cx);
    let pk_bytes = pk_buffer.as_slice(&cx);
    let tk_bytes = tk_buffer.as_slice(&cx);

    if pk_bytes.len() != PublicKey::BYTES {
        return cx.throw(res);
    }
    if tk_bytes.len() != Token::BYTES {
        return cx.throw(res);
    }

    let mut pk_size = [0u8; PublicKey::BYTES];
    pk_size.copy_from_slice(pk_bytes);
    let tk_size = <[u8; Token::BYTES]>::try_from(tk_bytes).unwrap();

    let ct_pk = PublicKey::from_bytes(&pk_size);
    let ct_tk = Token::from_bytes(&tk_size);

    match (ct_pk.is_some().unwrap_u8(), ct_tk.is_some().unwrap_u8()) {
        (1u8, 1u8) => {
            let pk = ct_pk.unwrap();
            let tk = ct_tk.unwrap();

            let r = pk.verify_token(id_bytes, &tk).unwrap_u8() == 1u8;

            Ok(JsBoolean::new(&mut cx, r))
        },
        (_, _) => {
            return cx.throw(res);
        }
    }
}


/// @param ArrayBuffer `token` - The token
/// @param ArrayBuffer `blinding_factor` - The blinding factor
/// @returns ArrayBuffer `new_token` -The token with the blinding factor applied
fn add_blinding(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let ja = JsArrayBuffer::new(&mut cx, 0)?;
    let blinding_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let tk_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;

    let blinding_bytes = blinding_buffer.as_slice(&cx);
    let tk_bytes = tk_buffer.as_slice(&cx);

    if tk_bytes.len() != Token::BYTES {
        return cx.throw(ja);
    }
    let tk_size = <[u8; Token::BYTES]>::try_from(tk_bytes).unwrap();

    let ct_tk = Token::from_bytes(&tk_size);

    if ct_tk.is_none().unwrap_u8() == 1u8 {
        return cx.throw(ja);
    }
    let tk = ct_tk.unwrap();

    let new_tk = tk - Blinding::new(blinding_bytes);
    Ok(slice_to_js_array_buffer!(&new_tk.to_bytes(), cx))
}


/// @param ArrayBuffer `token` - The token
/// @param ArrayBuffer `blinding_factor` - The blinding factor
/// @returns ArrayBuffer `new_token` -The token with the blinding factor removed
fn remove_blinding(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let ja = JsArrayBuffer::new(&mut cx, 0)?;

    let blinding_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let tk_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;

    let blinding_bytes = blinding_buffer.as_slice(&cx);
    let tk_bytes = tk_buffer.as_slice(&cx);

    if tk_bytes.len() != Token::BYTES {
        return cx.throw(ja);
    }
    let tk_size = <[u8; Token::BYTES]>::try_from(tk_bytes).unwrap();

    let ct_tk = Token::from_bytes(&tk_size);

    if ct_tk.is_none().unwrap_u8() == 1u8 {
        return cx.throw(ja);
    }
    let tk = ct_tk.unwrap();

    let new_tk = tk + Blinding::new(blinding_bytes);
    Ok(slice_to_js_array_buffer!(&new_tk.to_bytes(), cx))
}


/// @param ArrayBuffer `token` - The token
/// @param ArrayBuffer `id` - The identifier
/// @param Array<ArrayBuffer> `blindings` - The blinding factors
/// @param ArrayBuffer `nonce` - The proof nonce
fn create_proof(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let ja = JsArrayBuffer::new(&mut cx, 0)?;

    let tk_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let blinding_factor_buffer: Vec<Handle<JsValue>> = obj_field_to_vec!(cx, 2);
    let nonce_buffer: Handle<JsArrayBuffer> = cx.argument(3)?;

    let tk_bytes = tk_buffer.as_slice(&cx);
    let id = id_buffer.as_slice(&cx).to_vec();
    let nonce = nonce_buffer.as_slice(&cx).to_vec();

    if tk_bytes.len() != Token::BYTES {
        return cx.throw(ja);
    }

    let tk_size = <[u8; Token::BYTES]>::try_from(tk_bytes).unwrap();

    let ct_tk = Token::from_bytes(&tk_size);

    if ct_tk.is_none().unwrap_u8() == 1u8 {
        return cx.throw(ja);
    }
    let mut bs = Vec::new();
    for b in &blinding_factor_buffer {
        let a: Handle<JsArrayBuffer> = b.downcast_or_throw(&mut cx)?;
        let blinding = Blinding::new(a.as_slice(&cx));
        bs.push(blinding);
    }

    let rng = rand::thread_rng();
    let token = ct_tk.unwrap();
    match Proof::new(&token, &bs, &id, &nonce, rng) {
        None => cx.throw(ja),
        Some(proof) => Ok(slice_to_js_array_buffer!(&proof.to_bytes(), cx))
    }
}


/// @param ArrayBuffer `proof` - The proof
/// @param ArrayBuffer `public_key` - The verification key
/// @param ArrayBuffer `id` - The identifier
/// @param ArrayBuffer `nonce` - The proof nonce
/// @returns True if valid, false otherwise
fn verify_proof(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let f = JsBoolean::new(&mut cx, false);

    let proof_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;
    let public_key_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(2)?;
    let nonce_buffer: Handle<JsArrayBuffer> = cx.argument(3)?;

    let pf_bytes = proof_buffer.as_slice(&cx);
    let pk_bytes = public_key_buffer.as_slice(&cx);
    let id = id_buffer.as_slice(&cx);
    let nonce = nonce_buffer.as_slice(&cx);

    if pk_bytes.len() != PublicKey::BYTES {
        return cx.throw(f);
    }
    if pf_bytes.len() != Proof::BYTES {
        return cx.throw(f);
    }
    let mut pk_size = [0u8; PublicKey::BYTES];
    pk_size.copy_from_slice(pk_bytes);

    let mut pf_size = [0u8; Proof::BYTES];
    pf_size.copy_from_slice(pf_bytes);

    let ct_pk = PublicKey::from_bytes(&pk_size);
    let ct_pf = Proof::from_bytes(&pf_size);

    match (ct_pk.is_some().unwrap_u8(), ct_pf.is_some().unwrap_u8()) {
        (1u8, 1u8) => {
            let pubkey = ct_pk.unwrap();
            let proof = ct_pf.unwrap();

            let res = proof.open(pubkey, id, nonce).unwrap_u8() == 1;
            Ok(JsBoolean::new(&mut cx, res))
        },
        (_, _) => cx.throw(f)
    }
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("newSecretKey", new_secret_key)?;
    cx.export_function("getPublicKey", get_public_key)?;
    cx.export_function("secretKeyFromSeed", secret_key_from_seed)?;
    cx.export_function("newToken", new_token)?;
    cx.export_function("verifyToken", verify_token)?;
    cx.export_function("addBlinding", add_blinding)?;
    cx.export_function("removeBlinding", remove_blinding)?;
    cx.export_function("createProof", create_proof)?;
    cx.export_function("verifyProof", verify_proof)?;
    Ok(())
}

// register_module!(mut cx, {
//     cx.export_function("newSecretKey", new_secret_key)?;
//     cx.export_function("getPublicKey", get_public_key)?;
//     cx.export_function("secretKeyFromSeed", secret_key_from_seed)?;
//     cx.export_function("newToken", new_token)?;
//     cx.export_function("verifyToken", verify_token)?;
//     cx.export_function("addBlinding", add_blinding)?;
//     cx.export_function("removeBlinding", remove_blinding)?;
//     cx.export_function("createProof", create_proof)?;
//     cx.export_function("verifyProof", verify_proof)?;
//     Ok(())
// });