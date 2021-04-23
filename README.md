# Oberon
A succinct ZKP protocol for authentication. It works by using techniques similar to
Identity-Based/Attribute-Based signatures.

**Executive Summary**: Oberon allows endpoints to issue multi-factor capable tokens to consumers
who can prove their validity with disclosing the tokens themselves without requiring email, SMS, or authenticator apps. Endpoints
only need to store a single public key and not any tokens. An attacker that breaks
into the server doesn't have any password/token files to steal and only would see
a public key. The proof of token validity is only 96 bytes while the token itself
is only 48 bytes. The issuing party and verifying servers can be separate entities.

**In depth details**


## Primitives

### Curve and Bilinear Maps

The protocol uses pairing-friendly curves as the basic building block under the hood.

This implementation uses [BLS12-381](https://hackmd.io/@benjaminion/bls12-381) but can easily change to any other pairing-friendly curve.

The curve **C** parameters are denoted as

- **k**: The security parameter in bits.
- **p**: The field modulus
- **q**: The subgroup order
- **G<sub>1</sub>**: Points in the cyclic group of order **p**
- **G<sub>2</sub>**: Points in the multiplicative group of order **p<sup>2</sup>**
- **e()**: A pairing function that takes **G<sub>1</sub>** and **G<sub>2</sub>** and returns a result in the multiplicative group **G<sub>T</sub>** in **p<sup>12</sup>**
- **P**: The base point in **G<sub>1</sub>**
- **<span style="text-decoration:overline">P</span>**: The base point in **G<sub>2</sub>**
- **1<sub>G1</sup>**: The point at infinity in **G<sub>1</sub>**
- **1<sub>G2</sup>**: The point at infinity in **G<sub>2</sub>**
- **1<sub>GT</sup>**: The point at infinity in **G<sub>T</sub>**

Scalars operate in **Z<sub>q</sub>** and are denoted as lower case letters.
Scalars are represented with 32 bytes with BLS12-381.

Points operating in **G<sub>1</sub>** are denoted as capital letters.
**G<sub>1</sub>** points in BLS12-381 are 48 bytes compressed and 96 bytes uncompressed.

Points operating in **G<sub>2</sub>** are denoted as capital letters with an overline.
**G<sub>2</sub>** points in BLS12-381 are 96 bytes compressed and 192 bytes uncompressed.

### Hash to Curve

Oberon uses [Hash to curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)
to map arbitrary byte sequences to random points with unknown discrete logs.

This is denoted as H<sub>G1</sub> for hashing to a point in **G<sub>1</sub>**.

The hash to curve standard demands a unique DST to be defined. Oberon uses

`OBERON_BLS12381G1_XOF:SHAKE-256_SSWU_RO_`

### Hash to Field

Oberon hashes arbitrary byte sequences to a field element. The tricky part here is
to generate enough bytes such that the result is distributed uniformly random. 

A common approach is to use SHA256 to hash to byte sequence then reduce modulo **q**.
However, this results in a biased result that isn't uniform. Instead more bytes
should be generated then reduced modulo **q**. 
The number of bytes is calculated with L = ceil((ceil(log2(p)) + k) / 8).
For BLS12-381 this is L=48 bytes.

This implementation uses SHAKE-256 to output 48 bytes.

Hash to field is denoted as H<sub>q</sub>.

### Signatures

Oberon uses [BLS keys](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/)
in combination with [Pointcheval Saunders](https://eprint.iacr.org/2015/525) (PS) signatures
with improvements in [Reassessing Security of PS signatures](https://eprint.iacr.org/2017/1197) to be secure under
Existential Unforgeability against Adaptively Chosen Message Attacks (EUF-CMA).

### Notations

- a || b: is the byte concatenation of two elements a, b
- <span style="text-decoration: underline;">&larr;</span> **Z<sub>q</sub>**: is a random number in the field **Z<sub>q</sub>**
- **id** is the user’s identification string

## Algorithms

Oberon has the following algorithms:

### KeyGen

By default, Oberon only signs a user’s identity string **id**, but PS signatures
support many attributes if needed with the tradeoff that keys get bigger but not the token.

KeyGen(**C**)

Generate BLS keys and set them for

w, <span style="text-decoration:overline">W</span>, 
x, <span style="text-decoration:overline">X</span>, 
y, <span style="text-decoration:overline">Y</span>

The output is 

The secret key **sk**={w, x, y}

The public key **pk**={<span style="text-decoration:overline">W</span>, <span style="text-decoration:overline">X</span>, <span style="text-decoration:overline">Y</span>}

### Sign

Sign creates a token to be given to a user and works as follows

Sign(**sk**, **id**)

- m = H<sub>q</sub>(**id**)
- if m = 0 abort
- m' = H<sub>q</sub>(m)
- if m' = 0 abort
- U = H<sub>G1</sub>(m')
- if U = 1<sub>G1</sub> abort
- &sigma; = (x + m' * w + m * y) * U 
- if &sigma; = 1<sub>G1</sub> abort

Output token is &sigma;

### Blinding factor

Oberon can use a blinding factor in combination with the normal token
to *blind* the original token such that without knowledge of the 2nd factor,
the token is useless.
Blinding factors can be computed by using H<sub>G1</sub> on any arbitrary input.

For example, the user could select a 6-digit pin that needs to be entered
each time they want to use it. To require the pin to use the token, the following can be computed

- B = H<sub>G1</sub>(pin)
- &sigma;' = &sigma; - B

Store &sigma;'

Multiple blinding factors can be applied in a similar manner. Each blinding factor
can be different based on the platform where the token resides.

### Verify

 Verify takes a token and checks its validity. Meant to be run by the token holder
 since the token should never be disclosed to anyone.
 
Verify(**pk**, **id**, &sigma;)

- m = H<sub>q</sub>(**id**)
- if m = 0 return false
- m' = H<sub>q</sub>(m)
- if m' = 0 return false
- U = H<sub>G1</sub>(m')
- if U = 1<sub>G1</sub> return false
- return e(U, <span style="text-decoration:overline">X</span> + m * <span style="text-decoration:overline">Y</span> + m' * <span style="text-decoration:overline">W</span>) * e(&sigma;, -<span style="text-decoration:overline">P</span>) = 1<sub>GT</sub>

m, m', and U can be cached by the holder for performance if desired in which case
those steps can be skipped.

### Prove

Prove creates a zero-knowledge proof of a valid token instead of sending the token itself.
This allows the token to be reused while minimizing the risk of correlation.

Below is the algorithm for Prove assuming a blind factor with a pin.

Prove(&sigma;', **id**, [opt]n)

- m = H<sub>q</sub>(**id**)
- if m = 0 abort
- m' = H<sub>q</sub>(m)
- if m' = 0 abort
- U = H<sub>G1</sub>(m')
- if U = 1<sub>G1</sub> abort
- if n &ne; &empty; ; d = n ; else d = Unix timestamp in milliseconds
- t = H<sub>q</sub>(id || d)
- r <span style="text-decoration: underline;">&larr;</span> Z<sub>q</sub>
- U' = r * U
- &pi; = t * U' + r * &sigma;' + r * B    

Output &pi;, U', d, id

### Open

Open validates whether a proof is valid against a specific public key and is fresh enough.

Open(**pk**, &pi;, U', d, id)

- if U'= 1<sub>G1</sub> or &pi; = 1<sub>G1</sub> return false
- if d is timestamp then now() - d < threshold return false
- m = H<sub>q</sub>(**id**)
- if m = 0 abort
- m' = H<sub>q</sub>(m)
- if m' = 0 abort
- t = H<sub>q</sub>(id || d)
- return e(U', <span style="text-decoration:overline">X</span> + m * <span style="text-decoration:overline">Y</span> + m' * <span style="text-decoration:overline">W</span> + t * <span style="text-decoration:overline">P</span>) * e(&pi;, -<span style="text-decoration:overline">P</span>) = 1<sub>GT</sub>

## Other notes

PS signatures support blind signatures methods such that **id** could be blinded before
being signed by the token issuer.

They also support multiple attributes that can be added to the signature with the cost of an additional 
BLS keypair per attribute.

Oberon is meant to be simple and for now doesn't handle these features but might in future work.

## Threshold

Since the keys are BLS based, they can use any suitable threshold key gen and sign technique.

This process should be handled outside of Oberon. Another crate will probably be created for this.