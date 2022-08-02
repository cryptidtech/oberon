#!/usr/bin/python3

import pdb
import os
import sys
from ctypes import (
    CDLL,
    POINTER,
    Structure,
    byref,
    string_at,
    c_char_p,
    c_int32,
    c_int64,
    c_uint64,
    c_ubyte,
)

from ctypes.util import find_library
from typing import Optional, Union

LIB: CDLL = None

class FfiByteBuffer(Structure):
    """A byte buffer allocated by python."""
    _fields_ = [
        ("length", c_int64),
        ("data", POINTER(c_ubyte)),
    ]


class FfiError(Structure):
    """An error allocated by python."""
    _fields_ = [
        ("code", c_int32),
        ("message", c_char_p),
    ]


def _decode_bytes(arg: Optional[Union[str, bytes, FfiByteBuffer]]) -> bytes:
    if isinstance(arg, FfiByteBuffer):
        return string_at(arg.data, arg.length)
    if isinstance(arg, memoryview):
        return string_at(arg.obj, arg.nbytes)
    if isinstance(arg, bytearray):
        return arg
    if arg is not None:
        if isinstance(arg, str):
            return arg.encode("utf-8")
    return bytearray()


def _encode_bytes(arg: Optional[Union[str, bytes, FfiByteBuffer]]) -> FfiByteBuffer:
    if isinstance(arg, FfiByteBuffer):
        return arg
    buf = FfiByteBuffer()
    if isinstance(arg, memoryview):
        buf.length = arg.nbytes
        if arg.contiguous and not arg.readonly:
            buf.data = (c_ubyte * buf.length).from_buffer(arg.obj)
        else:
            buf.data = (c_ubyte * buf.length).from_buffer_copy(arg.obj)
    elif isinstance(arg, bytearray):
        buf.length = len(arg)
        if buf.length > 0:
            buf.data = (c_ubyte * buf.length).from_buffer(arg)
    elif arg is not None:
        if isinstance(arg, str):
            arg = arg.encode("utf-8")
        buf.length = len(arg)
        if buf.length > 0:
            buf.data = (c_ubyte * buf.length).from_buffer_copy(arg)
    return buf


def _load_library(lib_name: str) -> CDLL:
    lib_prefix_mapping = {"win32": ""}
    lib_suffix_mapping = {"darwin": ".dylib", "win32": ".dll"}
    try:
        os_name = sys.platform
        lib_prefix = lib_prefix_mapping.get(os_name, "lib")
        lib_suffix = lib_suffix_mapping.get(os_name, ".so")
        lib_path = os.path.join(
            os.path.dirname(__file__), f"{lib_prefix}{lib_name}{lib_suffix}"
        )
        return CDLL(lib_path)
    except KeyError:
        print ("Unknown platform for shared library")
    except OSError:
        print ("Library not loaded from python package")

    lib_path = find_library(lib_name)
    if not lib_path:
        if sys.platform == "darwin":
            ld = os.getenv("DYLD_LIBRARY_PATH")
            lib_path = os.path.join(ld, "liboberon.dylib")
            if os.path.exists(lib_path):
                return CDLL(lib_path)

            ld = os.getenv("DYLD_FALLBACK_LIBRARY_PATH")
            lib_path = os.path.join(ld, "liboberon.dylib")
            if os.path.exists(lib_path):
                return CDLL(lib_path)
        elif sys.platform != "win32":
            ld = os.getenv("LD_LIBRARY_PATH")
            lib_path = os.path.join(ld, "liboberon.so")
            if os.path.exists(lib_path):
                return CDLL(lib_path)

        raise Exception(f"Error loading library: {lib_name}")
    try:
        return CDLL(lib_path)
    except OSError as e:
        raise Exception(f"Error loading library: {lib_name}")


def _get_library() -> CDLL:
    global LIB
    if LIB is None:
        LIB = _load_library("oberon")

    return LIB


def _get_func(fn_name: str):
    return getattr(_get_library(), fn_name)


def _get_size(fn_name: str) -> int:
    lib_fn = _get_func(fn_name)
    return lib_fn()


def secret_key_size() -> int:
    return _get_size("oberon_secret_key_size")


def public_key_size() -> int:
    return _get_size("oberon_public_key_size")


def token_size() -> int:
    return _get_size("oberon_token_size")


def blinding_size() -> int:
    return _get_size("oberon_blinding_size")


def proof_size() -> int:
    return _get_size("oberon_proof_size")


def _free_buffer(buffer: FfiByteBuffer):
    lib_fn = _get_func("oberon_byte_buffer_free")
    lib_fn(byref(buffer))


def _free_string(err: FfiError):
    lib_fn = _get_func("oberon_string_free")
    lib_fn(byref(err))


def _free_handle(handle: c_int64, err: FfiError):
    lib_fn = _get_func("oberon_create_proof_free")
    lib_fn(handle, byref(err))


def new_secret_key() -> bytes:
    buffer = FfiByteBuffer()
    lib_fn = _get_func("oberon_new_secret_key")
    lib_fn(byref(buffer))

    result = _decode_bytes(buffer)
    #_free_buffer(buffer)
    return result
        

def get_public_key(secret_key: bytes) -> bytes:
    """Return the corresponding public key from a secret key
    if the secret key is well-formed.
    """
    secret_key = _encode_bytes(secret_key)
    public_key = FfiByteBuffer()
    err = FfiError()
    lib_fn = _get_func("oberon_get_public_key")
    result = lib_fn(secret_key, byref(public_key), byref(err))

    if result == 0:
        out = _decode_bytes(public_key)
        #_free_buffer(public_key)
        return out
    else:
        message = string_at(err.message)
        #_free_string(err)
        raise Exception(message)


def secret_key_from_seed(seed: bytes) -> bytes:
    """Create a secret key from a private seed."""
    i = _encode_bytes(seed)
    buffer = FfiByteBuffer()
    lib_fn = _get_func("oberon_secret_key_from_seed")
    lib_fn(i, byref(buffer))
    
    result = _decode_bytes(buffer)
    #_free_buffer(buffer)
    return result


def new_token(secret_key: bytes, identifier: bytes) -> bytes:
    """Create a new token if the secret key is well-formed."""
    sk = _encode_bytes(secret_key)
    id = _encode_bytes(identifier)
    token = FfiByteBuffer()
    err = FfiError()

    lib_fn = _get_func("oberon_new_token")
    result = lib_fn(sk, id, byref(token), byref(err))
    if result == 0:
        out = _decode_bytes(token)
        #_free_buffer(token)
        return out
    else:
        message = string_at(err.message)
        #_free_string(err)
        raise Exception(message)


def verify_token(token: bytes, public_key: bytes, identifier: bytes) -> bool:
    """Check if this token and identifier can be verified with this public key."""
    tk = _encode_bytes(token)
    pk = _encode_bytes(public_key)
    id = _encode_bytes(identifier)
    err = FfiError()
    lib_fn = _get_func("oberon_verify_token")
    result = lib_fn(tk, pk, id, byref(err))
    if result == 0:
        return True
    elif err.code != 0:
        message = string_at(err.message)
        #_free_string(err)
        raise Exception(message)
    else:
        return False


def add_blinding(old_token: bytes, blinding: bytes) -> bytes:
    """Add a blinding factor to the token."""
    tk = _encode_bytes(old_token)
    b = _encode_bytes(blinding)
    err = FfiError()
    new = FfiByteBuffer()
    lib_fn = _get_func("oberon_add_blinding")
    result = lib_fn(tk, b, byref(new), byref(err))

    if result == 0:
        out = _decode_bytes(new)
        #_free_buffer(new)
        return out
    else:
        message = string_at(err.message)
        #_free_string(err)
        raise Exception(message)


def remove_blinding(old_token: bytes, blinding: bytes) -> bytes:
    """Remove a blinding factor to the token."""
    tk = _encode_bytes(old_token)
    b = _encode_bytes(blinding)
    err = FfiError()
    new = FfiByteBuffer()
    lib_fn = _get_func("oberon_remove_blinding")
    result = lib_fn(tk, b, byref(new), byref(err))

    if result == 0:
        out = _decode_bytes(new)
        #_free_buffer(new)
        return out
    else:
        message = string_at(err.message)
        #_free_string(err)
        raise Exception(message)


def create_proof(token: bytes, identifier: bytes, blindings: list[bytes], nonce: bytes) -> bytes:
    tk = _encode_bytes(token)
    id = _encode_bytes(identifier)
    n = _encode_bytes(nonce)
    err = FfiError()
    lib_fn = _get_func("oberon_create_proof_init")
    lib_fn.restype = c_uint64

    handle = lib_fn(byref(err))
    if handle == 0:
        message = string_at(err.message)
        #_free_string(err)
        raise Exception(message)

    handle = c_uint64(handle)

    lib_fn = _get_func("oberon_create_proof_set_token")
    result = lib_fn(handle, tk, byref(err))
    if result != 0:
        message = string_at(err.message)
        #_free_string(err)
        _free_handle(handle, err)
        raise Exception(message)

    lib_fn = _get_func("oberon_create_proof_set_id")
    result = lib_fn(handle, id, byref(err))
    if result != 0:
        message = string_at(err.message)
        #_free_string(err)
        _free_handle(handle, err)
        raise Exception(message)

    lib_fn = _get_func("oberon_create_proof_set_nonce")
    result = lib_fn(handle, n, byref(err))
    if result != 0:
        message = string_at(err.message)
        #_free_string(err)
        _free_handle(handle, err)
        raise Exception(message)

    lib_fn = _get_func("oberon_create_proof_add_blinding")
    for blinder in blindings:
        b = _encode_bytes(blinder)
        result = lib_fn(handle, b, byref(err))
        if result != 0:
            message = string_at(err.message)
            #_free_string(err)
            _free_handle(handle, err)
            raise Exception(message)

    lib_fn = _get_func("oberon_create_proof_finish")
    proof = FfiByteBuffer()
    result = lib_fn(handle, byref(proof), byref(err))
    if result == 0:
        _free_handle(handle, err)
        out = _decode_bytes(proof)
        #_free_buffer(new)
        return out
    else:
        message = string_at(err.message)
        _free_handle(handle, err)
        #_free_string(err)
        raise Exception(message)


def verify_proof(proof: bytes, public_key: bytes, identifier: bytes, nonce: bytes) -> bool:
    pf = _encode_bytes(proof)
    pk = _encode_bytes(public_key)
    id = _encode_bytes(identifier)
    n = _encode_bytes(nonce)
    err = FfiError()

    lib_fn = _get_func("oberon_verify_proof")
    result = lib_fn(pf, pk, id, n, byref(err))
    if result == 0:
        return True
    elif err.code != 0:
        message = string_at(err.message)
        #_free_string(err)
        raise Exception(message)
    else:
        return False


if __name__ == "__main__":
    pdb.set_trace()
    sk = new_secret_key()
    pk = get_public_key(sk)
    id = bytes("ed25519".encode("utf-8"))
    token = new_token(sk, id)
    print("verify: ", verify_token(token, pk, id))
    proof = create_proof(token, id, [], sk)
    print("open: ", verify_proof(proof, pk, id, sk))
