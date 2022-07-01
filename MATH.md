<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/KaTeX/0.5.1/katex.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/github-markdown-css/2.2.1/github-markdown.css"/>

## Primitives

### Curve and Bilinear Maps

The protocol uses pairing-friendly curves as the basic building block under the hood.

This implementation uses [BLS12-381](https://hackmd.io/@benjaminion/bls12-381) but can easily change to any other pairing-friendly curve.

The curve <img src="https://render.githubusercontent.com/render/math?math=C"> parameters are denoted as

- <img src="https://render.githubusercontent.com/render/math?math=k">: The security parameter in bits.
- <img src="https://render.githubusercontent.com/render/math?math=p">: The field modulus
- <img src="https://render.githubusercontent.com/render/math?math=q">: The subgroup order
- <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_1">: Points in the cyclic group of order <img src="https://render.githubusercontent.com/render/math?math=p">
- <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_2">: Points in the multiplicative group of order <img src="https://render.githubusercontent.com/render/math?math=p^2">
- <img src="https://render.githubusercontent.com/render/math?math=e()">: A pairing function that takes <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_1"> and <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_2"> and returns a result in the multiplicative group <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_T"> in <img src="https://render.githubusercontent.com/render/math?math=p^12">
- <img src="https://render.githubusercontent.com/render/math?math=P">: The base point in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_1">
- <img src="https://render.githubusercontent.com/render/math?math=\widetilde{P}">: The base point in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_2">
- <img src="https://render.githubusercontent.com/render/math?math=1_{\mathbb{G}_1}">: The point at infinity in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_1">
- <img src="https://render.githubusercontent.com/render/math?math=1_{\mathbb{G}_2}">: The point at infinity in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_2">
- <img src="https://render.githubusercontent.com/render/math?math=1_{\mathbb{G}_T}">: The point at infinity in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_T">

Scalars operate in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{Z}_q"> and are denoted as lower case letters.
Scalars are represented with 32 bytes with BLS12-381.

Points operating in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_1"> are denoted as capital letters.
<img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_1"> points in BLS12-381 are 48 bytes compressed and 96 bytes uncompressed.

Points operating in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_2"> are denoted as capital letters with a wide tilde.
<img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_2"> points in BLS12-381 are 96 bytes compressed and 192 bytes uncompressed.

### Hash to Curve

Oberon uses [Hash to curve](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/)
to map arbitrary byte sequences to random points with unknown discrete logs.

This is denoted as <img src="https://render.githubusercontent.com/render/math?math=H_{\mathbb{G}_1}"> for hashing to a point in <img src="https://render.githubusercontent.com/render/math?math=\mathbb{G}_1">.

The hash to curve standard demands a unique DST to be defined. Oberon uses

`OBERON_BLS12381G1_XOF:SHAKE-256_SSWU_RO_`

### Hash to Field

Oberon hashes arbitrary byte sequences to a field element. The tricky part here is
to generate enough bytes such that the result is distributed uniformly random.

A common approach is to use SHA256 to hash to byte sequence then reduce modulo <img src="https://render.githubusercontent.com/render/math?math=q">.
However, this results in a biased result that isn't uniform. Instead more bytes
should be generated then reduced modulo <img src="https://render.githubusercontent.com/render/math?math=q">.
The number of bytes is calculated with L = ceil((ceil(log2(p)) + k) / 8).
For BLS12-381 this is L=48 bytes.

This implementation uses SHAKE-256 to output 48 bytes.

Hash to field is denoted as <img src="https://render.githubusercontent.com/render/math?math=H_{\mathbb{Z}_q}">.

Hash to field uses the domain separation tag `OBERON_BLS12381FQ_XOF:SHAKE-256_`

### Signatures

Oberon uses [BLS keys](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/)
in combination with [Pointcheval Saunders](https://eprint.iacr.org/2015/525) (PS) signatures
with improvements in [Reassessing Security of PS signatures](https://eprint.iacr.org/2017/1197) to be secure under
Existential Unforgeability against Adaptively Chosen Message Attacks (EUF-CMA).

### Notations

- a || b: is the byte concatenation of two elements a, b
- <img src="https://render.githubusercontent.com/render/math?math=\xleftarrow{\$}\mathbb{Z}_q">: is a random number in the field <img src="https://render.githubusercontent.com/render/math?math=\mathbb{Z}_q">
- <img src="https://render.githubusercontent.com/render/math?math=id"> is the user’s identification string

## Algorithms

Oberon has the following algorithms:

### KeyGen

By default, Oberon only signs a user’s identity string <img src="https://render.githubusercontent.com/render/math?math=id">, but PS signatures
support many attributes if needed with the tradeoff that keys get bigger but not the token.

KeyGen(<img src="https://render.githubusercontent.com/render/math?math=C">)

Generate BLS keys and set them for

<img src="https://render.githubusercontent.com/render/math?math=w, \widetilde{W}">
<img src="https://render.githubusercontent.com/render/math?math=x, \widetilde{X}">
<img src="https://render.githubusercontent.com/render/math?math=y, \widetilde{Y}">

The output is

The secret key <img src="https://render.githubusercontent.com/render/math?math=sk = \{w, x, y\}"> and is 96 bytes.

The public key <img src="https://render.githubusercontent.com/render/math?math=pk = \{\widetilde{W}, \widetilde{X}, \widetilde{Y}\}"> and is 288 bytes.

### Sign

Sign creates a token to be given to a user and works as follows

Sign(<img src="https://render.githubusercontent.com/render/math?math=sk">, <img src="https://render.githubusercontent.com/render/math?math=id">)

- <img src="https://render.githubusercontent.com/render/math?math=m = H_{\mathbb{Z}_q}(id)">
- if <img src="https://render.githubusercontent.com/render/math?math=m = 0"> abort
- <img src="https://render.githubusercontent.com/render/math?math=m' = H_{\mathbb{Z}_q}(m)">
- if <img src="https://render.githubusercontent.com/render/math?math=m' = 0"> abort
- <img src="https://render.githubusercontent.com/render/math?math=U = H_{\mathbb{G}_1}(m')">
- if <img src="https://render.githubusercontent.com/render/math?math=U = 1_{\mathbb{G}_1}"> abort
- <img src="https://render.githubusercontent.com/render/math?math=\sigma = (x %2B m'.w %2B m.y) \cdot U"> 
- if <img src="https://render.githubusercontent.com/render/math?math=\sigma = 1_{\mathbb{G}_1}"> abort

Output token is <img src="https://render.githubusercontent.com/render/math?math=\sigma">

### Blinding factor

Oberon can use a blinding factor in combination with the normal token
to *blind* the original token such that without knowledge of the 2nd factor,
the token is useless.
Blinding factors can be computed by using H<sub>G1</sub> on any arbitrary input.

For example, the user could select a 6-digit pin that needs to be entered
each time they want to use it. To require the pin to use the token, the following can be computed

- <img src="https://render.githubusercontent.com/render/math?math=B = H_{\mathbb{G}_1}(pin)">
- <img src="https://render.githubusercontent.com/render/math?math=\sigma' = \sigma - B">

Store <img src="https://render.githubusercontent.com/render/math?math=\sigma'">

Multiple blinding factors can be applied in a similar manner. Each blinding factor
can be different based on the platform where the token resides.

### Verify

Verify takes a token and checks its validity. Meant to be run by the token holder
since the token should never be disclosed to anyone.

Verify(<img src="https://render.githubusercontent.com/render/math?math=pk">, <img src="https://render.githubusercontent.com/render/math?math=id">, <img src="https://render.githubusercontent.com/render/math?math=\sigma">)

- <img src="https://render.githubusercontent.com/render/math?math=m = H_{\mathbb{G}_1}(id)">
- if <img src="https://render.githubusercontent.com/render/math?math=m = 0"> return false
- <img src="https://render.githubusercontent.com/render/math?math=m' = H_{\mathbb{Z}_q}(m)">
- if <img src="https://render.githubusercontent.com/render/math?math=m' = 0"> return false
- <img src="https://render.githubusercontent.com/render/math?math=U = H_{\mathbb{G}_1}(m')">
- if <img src="https://render.githubusercontent.com/render/math?math=U = 1_{\mathbb{G}_1}"> return false
- return <img src="https://render.githubusercontent.com/render/math?math=e(U, \widetilde{X} %2B m \cdot \widetilde{Y} %2B m' \cdot \widetilde{W}) . e(\sigma, -\widetilde{P}) = 1_{\mathbb{G}_1}">

<img src="https://render.githubusercontent.com/render/math?math=m, m', U"> can be cached by the holder for performance if desired in which case
those steps can be skipped.

### Prove

Prove creates a zero-knowledge proof of a valid token instead of sending the token itself.
This allows the token to be reused while minimizing the risk of correlation.

Below is the algorithm for Prove assuming a blind factor with a pin.

Prove(<img src="https://render.githubusercontent.com/render/math?math=\sigma'">, <img src="https://render.githubusercontent.com/render/math?math=id">, [opt] <img src="https://render.githubusercontent.com/render/math?math=n">)

- <img src="https://render.githubusercontent.com/render/math?math=m = H_{\mathbb{Z}_q}(id)">
- if <img src="https://render.githubusercontent.com/render/math?math=m = 0"> abort
- <img src="https://render.githubusercontent.com/render/math?math=m' = H_{\mathbb{Z}_q}(m)">
- if <img src="https://render.githubusercontent.com/render/math?math=m' = 0">  abort
- <img src="https://render.githubusercontent.com/render/math?math=U = H_{\mathbb{G}_1}(m')">
- if <img src="https://render.githubusercontent.com/render/math?math=U = 1_{\mathbb{G}_1}"> abort
- if <img src="https://render.githubusercontent.com/render/math?math=n \ne \empty"> ; <img src="https://render.githubusercontent.com/render/math?math=d = n"> ; else <img src="https://render.githubusercontent.com/render/math?math=d = ">Unix timestamp in milliseconds
- <img src="https://render.githubusercontent.com/render/math?math=r, t, tt \xleftarrow{\$} \mathbb{Z}_q*">
- <img src="https://render.githubusercontent.com/render/math?math=\widetilde{D} = t \cdot \widetilde{P}">
- <img src="https://render.githubusercontent.com/render/math?math=\widetilde{Dt} = tt \cdot \widetilde{P}">
- <img src="https://render.githubusercontent.com/render/math?math=U' = r \cdot U">
- <img src="https://render.githubusercontent.com/render/math?math=\pi = t \cdot U' %2B r \cdot \sigma' %2B r \cdot B">
- <img src="https://render.githubusercontent.com/render/math?math=c = H_{\mathbb{Z}_q}(id || U' || \pi || \widetilde{D} || \widetilde{Dt} || d)">
- <img src="https://render.githubusercontent.com/render/math?math=s = tt - c . t">

Output <img src="https://render.githubusercontent.com/render/math?math=\tau = \pi, U', \widetilde{D}, s, d, c, id">

### Open

Open validates whether a proof is valid against a specific public key and is fresh enough.

Open(<img src="https://render.githubusercontent.com/render/math?math=pk">, <img src="https://render.githubusercontent.com/render/math?math=\tau">)

- if <img src="https://render.githubusercontent.com/render/math?math=U' = 1_{\mathbb{G}_1}"> or <img src="https://render.githubusercontent.com/render/math?math=\pi = 1_{\mathbb{G}_1}"> return false
- if <img src="https://render.githubusercontent.com/render/math?math=d">is timestamp then <img src="https://render.githubusercontent.com/render/math?math=Now - d < th"> return false
- <img src="https://render.githubusercontent.com/render/math?math=m = H_{\mathbb{Z}_q}(id)"> 
- if <img src="https://render.githubusercontent.com/render/math?math=m = 0"> abort
- <img src="https://render.githubusercontent.com/render/math?math=m' = H_{\mathbb{Z}_q}(m)">
- if <img src="https://render.githubusercontent.com/render/math?math=m' = 0"> abort
- <img src="https://render.githubusercontent.com/render/math?math=\widetilde{Dt} = s \cdot \widetilde{P} %2B c \cdot \widetilde{D}">
- <img src="https://render.githubusercontent.com/render/math?math=\widetilde{c} = H_{\mathbb{Z}_q}(id || U' || \pi || \widetilde{D} || \widetilde{Dt} || d)">
- if <img src="https://render.githubusercontent.com/render/math?math=\widetilde{c} \ne c"> return False
- return <img src="https://render.githubusercontent.com/render/math?math=e(U', \widetilde{X} %2B m \cdot \widetilde{Y} %2B m' \cdot \widetilde{W} %2B \widetilde{D}). e(\pi, -\widetilde{P}) = 1_{\mathbb{G}_T}">

## Other notes

PS signatures support blind signatures methods such that <img src="https://render.githubusercontent.com/render/math?math=id"> could be blinded before
being signed by the token issuer.

They also support multiple attributes that can be added to the signature with the cost of an additional
BLS keypair per attribute.

Oberon is meant to be simple and for now doesn't handle these features but might in future work.

## Threshold

Since the keys are BLS based, they can use any suitable threshold key gen and sign technique.

This process should be handled outside of Oberon. Another crate will probably be created for this.
