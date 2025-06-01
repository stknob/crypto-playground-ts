# JS/TS Cryptography playground

### Disclaimer
:warning: This repository contains experimental implementations of various cryptographic protocols.<br>
The code has not been audited and may change at any time! __DO _NOT_ USE IN PRODUCTION!__

### Contents
- RFC 9494 - Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups
    - Suites: Ristretto255-SHA512, Decaf448-CSHAKE256, P256-SHA256, P384-SHA384, P521-SHA512
	- Modes: OPRF, VOPRF, POPRF
	- Single and batched operation

- draft-irtf-cfrg-opaque-18 - The OPAQUE Augmented PAKE Protocol (OPAQUE-3DH)
    - Suites: Ristretto255-SHA512, Decaf448-CSHAKE256, P256-SHA256, P384-SHA384, P521-SHA512

- NOPAQUE - OPAQUE without PAKE
    - Suites: Ristretto255-SHA512, Decaf448-CSHAKE256, P256-SHA256, P384-SHA384, P521-SHA512

