---
title: "Generic Hybrid PQ/T Key Encapsulation Mechanisms"
abbrev: generic-hybrid-kems
category: info

docname: draft-irtf-cfrg-generic-hybrid-kems-latest
submissiontype: IRTF
consensus: false
v: 3
workgroup: "Crypto Forum"

author:
 -
    fullname: Deirdre Connolly
    organization: SandboxAQ
    email: durumcrustulum@gmail.com

normative:
    FIPS203: DOI.10.6028/NIST.FIPS.203

informative:
  AVIRAM:
    target: https://mailarchive.ietf.org/arch/msg/tls/F4SVeL2xbGPaPB2GW_GkBbD_a5M/
    title: "[TLS] Combining Secrets in Hybrid Key Exchange in TLS 1.3"
    date: 2021-09-01
    author:
      -
        ins: Nimrod Aviram
      -
        ins: Benjamin Dowling
      -
        ins: Ilan Komargodski
      -
        ins: Kenny Paterson
      -
        ins: Eyal Ronen
      -
        ins: Eylon Yogev
  BDG2020: https://eprint.iacr.org/2020/241.pdf
  GHP2018: https://eprint.iacr.org/2018/024.pdf
  I-D.driscoll-pqt-hybrid-terminology:
  LUCKY13:
    target: https://ieeexplore.ieee.org/iel7/6547086/6547088/06547131.pdf
    title: "Lucky Thirteen: Breaking the TLS and DTLS record protocols"
    author:
    -
      ins: N. J. Al Fardan
    -
      ins: K. G. Paterson
  RFC5869:
  RFC9180:
  XWING: https://eprint.iacr.org/2024/039.pdf

--- abstract

This document defines generic techniques to achive hybrid
post-quantum/traditional key encapsulation mechanisms (KEMs) from
post-quantum and traditional component algorithms that meet specified
security properties. Concrete instatiations of techniques are located in
another document.

--- middle

# Introduction {#intro}

## Motivation {#motivation}

There are many choices that can be made when specifying a hybrid KEM: the
constituent KEMs; their security levels; the combiner; and the hash within,
to name but a few. Having too many similar options are a burden to the
ecosystem.

The aim of this document is provide a small set of techniques for
constructing hybrid KEMs designed to achieve specific security properties
given conforming component algorithms, that should be suitable for the vast
majority of use cases.

## Design goals {#goals}

TODO

### Non-iteractive

These KEMs are a non-interactive means to establish a shared secret.  Using
KEMs in place of Diffie-Hellman key exchange can be done in some settings but
not all.

### Not authenticated

These KEMs are not _authenticated_.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document is consistent with all terminology defined in
{{I-D.driscoll-pqt-hybrid-terminology}}.

The following terms are used throughout this document:

- `concat(x0, ..., xN)`: returns the concatenation of byte
  strings. `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.

- `random(n)`: return a pseudorandom byte string of length `n` bytes produced by
  a cryptographically-secure random number generator.


# Key encapsulation mechanisms {#kems}

Key encapsulation mechanisms (KEMs) are cryptographic schemes that consist of
three algorithms:

- `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm,
  which generates a public encapsulation key `pk` and a secret
  decapsulation key `sk`.
- `Encaps(pk) -> (ct, shared_secret)`: A probabilistic encapsulation
  algorithm, which takes as input a public encapsulation key `pk` and
  outputs a ciphertext `ct` and shared secret `shared_secret`.
- `Decaps(sk, ct) -> shared_secret`: A decapsulation algorithm, which takes as
  input a secret decapsulation key `sk` and ciphertext `ct` and outputs
  a shared secret `shared_secret`.


# Hybrid KEM Security Properties

Hybrid KEM constructions aim to provide security by combining two or more
schemes so that security is preserved if all but one schemes are replaced by
an arbitrarily bad scheme.

## Hybrid Security

Informally, hybrid KEMs are secure if the `KDF` is secure, and if any one of
the components KEMs is secure: this is the 'hybrid' property.

## IND-CCA security

Also known as IND-CCA2 security for general public key encryption, for KEMs
that encapsulate a new random 'message' each time.

The notion of INDistinguishability against Chosen-Ciphertext Attacks
(IND-CCA) [RS92] is now widely accepted as the standard security notion for
asymmetric encryption schemes. IND-CCA security requires that no efficient
adversary can recognize which of two messages is encrypted in a given
ciphertext, even if the two candidate messages are chosen by the adversary
himself.

## LEAK-BIND-K-CT security

## LEAK-BIND-K-PK security

## CCR / C2PRI security

Ciphertext second preimage resistance for KEMs ([C2PRI][Xwing]). Related to
the ciphertext collision-freeness of the underlying PKE scheme of a
FO-transform KEM. Also called ciphertext collision resistance.

# Hybrid KEM Ingredients

To construct a secure hybrid KEM generically, we need some if not all of the
following ingredients:

## Key Derivation Function `KDF`

A secure key derivation function (KDF) that is modeled as a secure
pseudorandom function (PRF) in the [standard model][GHP2018] and independent
random oracle in the random oracle model (ROM).

## `label`

ASCII-encoded bytes that provide [oracle cloning][BDG2020] in the security
game via domain separation. The IND-CCA security of hybrid KEMs often
[relies][GHP2018] on the KDF function `KDF` to behave as an independent
random oracle, which the inclusion of the `label` achieves via domain
separation.

By design, the calls to `KDF` in these constructions and usage anywhere else
in higher level protoocl use separate input domains unless intentionally
duplicating the 'label' per concrete instance with fixed paramters. This
justifies modeling them as independent functions even if instantiated by the
same KDF. This domain separation is achieved by using prefix-free sets of
`label` values. Recall that a set is prefix-free if no element is a prefix of
another within the set.

Length diffentiation is sometimes used to achieve domain separation but as a
technique it is [brittle and prone to misuse][BDG2020] in practice so we
favor the use of an explicit post-fix label.

## Post-quantum KEM ciphertext `pq_CT`

The ciphertext produced from one encapsulation from the post-quantum
component KEM.

## Post-quantum KEM public encapsulation key `pq_PK`

The public encapsulation key produced by one key generation from the
post-quantum component KEM.

## Post-quantum KEM shared secret `pq_SS`

The shared secret produced from one encapsulation/decapsulation from the
post-quantum component KEM.

## Traditional KEM ciphertext `trad_CT`

The ciphertext (or equivalent) produced from one encapsulation from the
traditional component KEM.

## Traditional KEM public encapsulation key `trad_PK`

The public encapsulation key produced by one key generation from the
traditional component KEM.

## Traditional KEM shared secret `trad_SS`

The shared secret produced from one encapsulation/decapsulation from the
traditional component KEM.



# Hybrid KEM Generic Constructions

## Security requirements

### KDF as a secure PRF

A key derivation function (KDF) that is modeled as a secure pseudorandom
function (PRF) in the [standard model][GHP2018] and independent random oracle
in the random oracle model (ROM).

### IND-CCA-secure Post-Quantum KEM

A component post-quantum KEM that has IND-CCA security.

### Elliptic curve group where the Strong Diffie-Hellman problem (SDH) is hard

For these generic constructions, the traditional KEMs are [DH-KEM][RFC9180]
instantiated with a particular elliptic curve group. For one construction,
this requires Strong Diffie-Hellman security and to be modelable as a nominal
group.

### Fixed length

Every instantiation in concrete parameters of the generic constructions is
for fixed parameter sizes, KDF choice, and label, allowing the lengths to not
also be encoded into the generic construction. The label/KDF/component
algorithm parameter sets MUST be disjoint and non-colliding.

This document assumes and requires that the length of each public key,
ciphertext, and shared secret is fixed once the algorithm is fixed in the
concrete instantiations. This is the case for all concrete instantiations in
this document.


### LEAK-BIND-K-CT


<!-- # 'Chempat' construction -->

<!-- NOT INCLUDED BECAUSE NO SECURITY PROOF -->


# 'Kitchen Sink' construction:

~~~
def KitchenSink-KEM.SharedSecret():
    return KDF(concat(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT, trad_PK, label))
~~~

Label varies per combos such that the label will vary as the lengths and
other properties of the component algorithms vary. Otherwise we'd have to
hash the inputs to fixed lengths or encode lengths into the input.

# 'QSF' construction

Inspired by the generic QSF[^qsf] framework in [XWING], which leverages the
security properties of a KEM like ML-KEM and an inlined DH-KEM instance, to
elide other public data from the KDF input:

~~~
def QSF-KEM.SharedSecret():
    return KDF(concat(pq_SS, trad_SS, trad_CT, trad_PK, label))
~~~

Relies on PQ KEM having LEAK-BIND-K-CT and LEAK-BIND-K-PK and C2SPI security,
and an elliptic curve that can be modeled as a nominal group where the

To construct a concrete instance with IND-CCA security, the PQ component KEM
MUST have C2SPI security, the traditional KEM, as it is constructed


# Concrete Hybrid KEM Instances

       (I)  a hybrid of P-256 and ML-KEM-768,
       (II)  a hybrid of X25519 and ML-KEM-768, and,
       (III) a hybrid of P-384 and ML-KEM-1024.
##

## `QSF-SHA3-ML-KEM-768-P-256`

### FIPS

The selection of SHA-3 as the `KDF` is

## `QSF-SHA3-ML-KEM-1024-P-384`


# Security Considerations

Informally, these hybrid KEMs are secure if the `KDF` is secure, and either
the elliptic curve is secure, or the post-quantum KEM is secure: this is the
'hybrid' property.

More precisely for the concrete instantiations in this document, if SHA3-256,
SHA3-512, and SHAKE-256 may be modelled as a random oracle, then the IND-CCA
security of `QSF` constructions is bounded by the IND-CCA security of ML-KEM,
and the gap-CDH security of secp256n1, see [XWING].

## Fixed-length

Variable-length secrets are generally dangerous. In particular, using key
material of variable length and processing it using hash functions may result
in a timing side channel. In broad terms, when the secret is longer, the hash
function may need to process more blocks internally. In some unfortunate
circumstances, this has led to timing attacks, e.g. the Lucky Thirteen
[LUCKY13] and Raccoon [RACCOON] attacks.

Furthermore, [AVIRAM] identified a risk of using variable-length secrets when
the hash function used in the key derivation function is no longer
collision-resistant.

If concatenation were to be used with values that are not fixed-length, a
length prefix or other unambiguous encoding would need to be used to ensure
that the composition of the two values is injective and requires a mechanism
different from that specified in this document.

Therefore, this specification MUST only be used with algorithms which have
fixed-length shared secrets (after the variant has been fixed by the
algorithm identifier in the NamedGroup negotiation in Section 3.1).

# Out of Scope

Considerations that were considered and not included in these designs:

## More than two component KEMs

Design team decided to restrict the space to only two components, a
traditional and a post-quantum KEM.

## Parameterized output length

Not analyzed as part of any security proofs in the literature, and a
complicatation deemed unnecessary.

## Protocol-specific labels / info

The concrete instantiations have specific labels, protocol-specific
information is out of scope.

## Other Post-Quantum Primitives

There is demand for other hybrid variants that either use different
primitives (RSA, NTRU, Classic McEliece, FrodoKEM), parameters, or that use a
combiner optimized for a specific use case. Other use cases could be covered
in subsequent documents and not included here.


# IANA Considerations


## HPKE




--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
