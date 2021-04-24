[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache 2.0][license-image]

# Oberon
A succinct ZKP protocol for authentication. It works by using techniques similar to
Identity-Based/Attribute-Based signatures.

**Executive Summary**: Oberon allows endpoints to issue multi-factor capable tokens to consumers
who can prove their validity with disclosing the tokens themselves without requiring email, SMS, or authenticator apps. Endpoints
only need to store a single public key and not any tokens. An attacker that breaks
into the server doesn't have any password/token files to steal and only would see
a public key. The proof of token validity is only 96 bytes while the token itself
is only 48 bytes. The issuing party and verifying servers can be separate entities.

## In depth details

The cryptography can be found [here](CRYPTO.md)

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/oberon.svg
[crate-link]: https://crates.io/crates/oberon
[docs-image]: https://docs.rs/oberon/badge.svg
[docs-link]: https://docs.rs/oberon/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
