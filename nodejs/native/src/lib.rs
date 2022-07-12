use neon::{
    prelude::*,
    result::Throw,
};
use oberon::*;

macro_rules! slice_to_js_array_buffer {
    ($slice:expr, $cx:expr) => {{
        let mut result = JsArrayBuffer::new(&mut $cx, $slice.len() as u32)?;
        $cx.borrow_mut(&mut result, |d| {
            let bytes = d.as_mut_slice::<u8>();
            bytes.copy_from_slice($slice);
        });
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
    let secret_key_handle: Handle<JsArrayBuffer> = cx.argument(0)?;
    let secret_key_data = cx.borrow(&secret_key_handle, |data| data.as_slice::<u8>());
    let secret_key_bytes = <[u8; SecretKey::BYTES]>::try_from(secret_key_data).map_err(|_e| String::from("invalid secret key data"))?;
    let ct_sk = SecretKey::from_bytes(secret_key_bytes);
    if ct_sk.is_some().unwrap_u8() == 1u8 {
        let sk = ct_sk.unwrap();
        let pk = PublicKey::from(&sk);
        Ok(slice_to_js_array_buffer!(&pk.to_bytes(), cx))
    } else {
        Err(String::from("invalid secret key bytes")),
    }
}


/// @param ArrayBuffer `seed` - seed data
/// @returns ArrayBuffer `secret key` - the secret key
fn secret_key_from_seed(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let seed_handle: Handle<JsArrayBuffer> = cx.argument(0)?;
    let seed_data = cx.borrow(&secret_key_handle, |data| data.as_slice::<u8>());
    let sk = SecretKey::hash(seed_data);
    Ok(slice_to_js_array_buffer!(&sk.to_bytes(), cx))

}


/// @param ArrayBuffer `id` - The identifier to use for this token
/// @param ArrayBuffer `secretKey` - The secret key used for signing this token
/// @returns ArrayBuffer `token` - The token
fn new_token(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;
    let sk_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;

    let id_bytes = cx.borrow(&id_buffer, |data| data.as_slice::<u8>());
    let sk_bytes = cx.borrow(&sk_buffer, |data| data.as_slice::<u8>());

    if sk_bytes.len() != SecretKey::BYTES {
        return Err(Throw);
    }

    let sk = SecretKey::from_bytes(&<[u8; SecretKey::BYTES]>::try_from(sk_bytes).unwrap()).unwrap();
    let token = Token::new(&sk, id_bytes).ok_or_else(|| Throw)?;

    Ok(slice_to_js_array_buffer!(&token.to_bytes(), cx))
}


/// @param ArrayBuffer `token` - The token
/// @param ArrayBuffer `publicKey` - The public key used for verifying this token
/// @param ArrayBuffer `id` - The identifier to use for this token
/// @returns bool - True if valid, false otherwise
fn verify_token(mut cx: FunctionContext) -> JsResult<JsBoolean> {
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(2)?;
    let pk_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let tk_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;

    let id_bytes = cx.borrow(&id_buffer, |data| data.as_slice::<u8>());
    let pk_bytes = cx.borrow(&pk_buffer, |data| data.as_slice::<u8>());
    let tk_bytes = cx.borrow(&tk_buffer, |data| data.as_slice::<u8>());

    if pk_bytes.len() != PublicKey::BYTES {
        return Err(Throw);
    }
    if tk_bytes.len() != Token::BYTES {
        return Err(Throw);
    }

    let mut pk_size = [0u8; PublicKey::BYTES];
    pk_size.copy_from_slice(pk_bytes);
    let tk_size = <[u8; Token::BYTES]>::try_from(tk_bytes).unwrap();

    let ct_pk = PublicKey::from_bytes(&pk_size);
    let ct_tk = Token::from_bytes(&tk_size);

    match (ct_pk.is_some(), ct_tk.is_some()) {
        (1u8, 1u8) => {
            let pk = ct_pk.unwrap();
            let tk = ct_tk.unwrap();

            Ok(JsBoolean::new(&mut cx, pk.verify_token(id_bytes, &tk).unwrap_u8() == 1u8))
        },
        (_, _) => {
            Err(Throw)
        }
    }
}


/// @param ArrayBuffer `token` - The token
/// @param ArrayBuffer `blinding_factor` - The blinding factor
/// @returns ArrayBuffer `new_token` -The token with the blinding factor applied
fn add_blinding(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let blinding_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let tk_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;

    let blinding_bytes = cx.borrow(&pk_buffer, |data| data.as_slice::<u8>());
    let tk_bytes = cx.borrow(&tk_buffer, |data| data.as_slice::<u8>());

    if tk_bytes.len() != Token::BYTES {
        return Err(Throw);
    }
    let tk_size = <[u8; Token::BYTES]>::try_from(tk_bytes).unwrap();

    let ct_tk = Token::from_bytes(&tk_size);

    if ct_tk.is_some().unwrap_u8() == 1u8 {
        let tk = ct_tk.unwrap();

        let new_tk = tk - oberon::Blinding::new(blinding_bytes);
        Ok(slice_to_js_array_buffer!(&new_tk.to_bytes(), cx))
    }
}


/// @param ArrayBuffer `token` - The token
/// @param ArrayBuffer `blinding_factor` - The blinding factor
/// @returns ArrayBuffer `new_token` -The token with the blinding factor removed
fn remove_blinding(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let blinding_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let tk_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;

    let blinding_bytes = cx.borrow(&pk_buffer, |data| data.as_slice::<u8>());
    let tk_bytes = cx.borrow(&tk_buffer, |data| data.as_slice::<u8>());

    if tk_bytes.len() != Token::BYTES {
        return Err(Throw);
    }
    let tk_size = <[u8; Token::BYTES]>::try_from(tk_bytes).unwrap();

    let ct_tk = Token::from_bytes(&tk_size);

    if ct_tk.is_some().unwrap_u8() == 1u8 {
        let tk = ct_tk.unwrap();

        let new_tk = tk + oberon::Blinding::new(blinding_bytes);
        Ok(slice_to_js_array_buffer!(&new_tk.to_bytes(), cx))
    }
}


/// @param ArrayBuffer `token` - The token
/// @param ArrayBuffer `id` - The identifier
/// @param Array<ArrayBuffer> `blindings` - The blinding factors
/// @param ArrayBuffer `nonce` - The proof nonce
fn create_proof(mut cx: FunctionContext) -> JsResult<JsArrayBuffer> {
    let tk_buffer: Handle<JsArrayBuffer> = cx.argument(0)?;
    let id_buffer: Handle<JsArrayBuffer> = cx.argument(1)?;
    let blinding_factor_buffer: Vec<Handle<JsValue>> = obj_field_to_vec!(cx, 2);
    let nonce_buffer: Handle<JsArrayBuffer> = cx.argument(3)?;

    let tk_bytes = cx.borrow(&tk_buffer, |data| data.as_slice::<u8>());
    let id_bytes = cx.borrow(&id_buffer, |data| data.as_slice::<u8>());
    let nonce_bytes = cx.borrow(&nonce_buffer, |data| data.as_slice::<u8>());
}

register_module!(mut cx, {
    cx.export_function("newSecretKey", new_secret_key)?;
    cx.export_function("getPublicKey", get_public_key)?;
    cx.export_function("secretKeyFromSeed", secret_key_from_seed)?;
    cx.export_function("newToken", new_token)?;
    cx.export_function("verifyToken", verify_token)?;
    cx.export_function("addBlinding", add_blinding)?;
    cx.export_function("removeBlinding", remove_blinding)?;
});