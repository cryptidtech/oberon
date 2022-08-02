# Oberon Python

This is the python wrapper around the Oberon authentication scheme.

To install use `pip install oberon` but this only installs the python code.
Oberon is written as a C callable library and must be installed.

`curl -sSLO https://github.com/cryptidtech/oberon/releases/`

This library provides four classes: SecretKey, PublicKey, Token, Proof.


SecretKey is used to create new tokens.

PublicKey is used to verify tokens and token proofs.

Tokens are used for proving ownership in zero-knowledge proofs.
Tokens can be blinded provided the same blinders are supplied to create proofs.

Proofs demonstrate a valid token with an identifier.

```python
sk = SecretKey()
pk = sk.public_key()
id = bytes("ed25519".encode("utf-8"))
token = sk.new_token(id)
print("verify: ", token.verify(id, pk))
proof = token.create_proof(id, [], b"a random nonce")
print("open: ", proof.verify(id, pk, b"a random nonce"))
```

Blindings can be applied as follows

```python
blind_token = token.add_blinding(b"<4-6 digit pin>")
```

Blindings can be removed as follows

```python
token = blind_token.remove_blinding(b"<4-6 digit pin>")
```