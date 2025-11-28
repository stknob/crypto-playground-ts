## NOPAQUE - OPAQUE without the (P)AKE

### Disclaimer
:warning: This is an experimental implementation of a modified cryptographic protocol.<br>
The code has not been audited and may change at any time! __DO _NOT_ USE IN PRODUCTION!__

### Introduction
OPAQUE is a cryptographic protocol implementing a PAKE - Password Authenticated Key Exchange, which<br>
allows a client to authenticate against a server, without revealing any information about the password.

The result of a PAKE's authentication process is a shared session key, which can then be used for other<br>
cryptographic operations between both ends.

In addition to the shared (per-) session key, OPAQUE also generates a client-side, static export key, which,<br>
after the initial registration process, can only be recovered by the client by providing the correct credentials.<br>
This can be used by the client to encrypt (and later decrypt) data that is stored on the server.

### But what if...
... we do not care about the authentication aspect of OPAQUE and session key and only want to use the export key it<br>
produces as part of the registration and login processes?

NOPAQUE (pun intended) does exactly that: ripping out the AKE half of OPAQUE and reducing it to only the<br>
OPRF part that produces the export key.

### Status: Experimental
A basic version, based on the original OPRF part of OPAQUE is contained in this repository and (still) passes<br>
the relevant test vector components from the current draft-irtf-cfrg-opaque-18 spec.<br>
Changes include:

  - Removed the AKE components of OPAQUE (which is fairly easy) including unused parts of messages etc.
  - Changed the domain separation tag labels starting with "OPAQUE*" to "NOPAQUE*"<br>
    (NOTE: The draft-irtf-cfrg-opaque-18 spec tests temporarily override this to use the original ones)

Possible upcoming changes:

  - Switch from OPRF to POPRF and use the additional `info` parameter as a replacement for OPAQUE's `context`,<br>
    which we lost during the AKE removal. This will allow for additional domain separation between multiple<br>
    uses in a single application or multiple applications that access the same server.<br>
    Unfortunately, this will also make all of OPAQUE's test existing vectors unusable.<br>
    (Maybe call that version nopaque-poprf instead?)

### Links
- [RFC 9494 - Oblivious Pseudorandom Functions (OPRFs) Using Prime-Order Groups](https://datatracker.ietf.org/doc/html/rfc9497)
- [RFC 9807 - The OPAQUE Augmented Password-Authenticated Key Exchange (aPAKE) Protocol](https://datatracker.ietf.org/doc/html/rfc9807)
