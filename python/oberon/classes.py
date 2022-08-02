from .bindings import secret_key_size, public_key_size, token_size, \
    proof_size, new_secret_key, \
    get_public_key, secret_key_from_seed, new_token, \
    verify_token, add_blinding, remove_blinding, \
    create_proof, verify_proof

from typing import Optional, Union


def from_seed(seed):
    return SecretKey(secret_key_from_seed(seed))


class SecretKey:
    """A secret signing key"""

    def __init__(self, value: Optional[Union[str, bytes, list]] = None):
        data = bytes()
        if isinstance(value, memoryview):
            data = value
        if isinstance(value, bytearray):
            data = value
        if value is not None:
            if isinstance(value, str):
                data = value.encode("utf-8")
        if len(data) == secret_key_size():
            self.value = data
        else:
            self.value = new_secret_key()

    def public_key(self):
        return PublicKey(get_public_key(self.value))

    def new_token(self, identifier: bytes):
        return Token(new_token(self.value, identifier))

    def __bytes__(self):
        return self.value


class PublicKey:
    """A public verification key"""

    def __init__(self, value: bytes):
        if len(value) == public_key_size():
            self.value = value
        else:
            raise Exception("invalid public key size")

    def __bytes__(self):
        return self.value


class Token:
    """An Oberon Token"""

    def __init__(self, value: bytes):
        if len(value) == token_size():
            self.value = value
        else:
            raise Exception("invalid size")

    def __bytes__(self):
        return self.value

    def add_blinding(self, blinder: bytes):
        return Token(add_blinding(self.value, blinder))

    def remove_blinding(self, blinder: bytes):
        return Token(remove_blinding(self.value, blinder))

    def create_proof(self, identifier: bytes, blindings: list[bytes], nonce: bytes):
        return Proof(create_proof(self.value, identifier, blindings, nonce))

    def verify(self, identifier: bytes, public_key: PublicKey):
        return verify_token(self.value, public_key.value, identifier)


class Proof:
    """An oberon proof"""

    def __init__(self, value: bytes):
        if len(value) == proof_size():
            self.value = value
        else:
            raise Exception("invalid proof size")

    def __bytes__(self):
        return self.value

    def verify(self, identifier: bytes, public_key: PublicKey, nonce: bytes):
        return verify_proof(self.value, public_key.value, identifier, nonce)
