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
  ABHKLR2020:
    target: https://eprint.iacr.org/2020/1499.pdf
    title: "Analysing the HPKE Standard"
    date: 2020
    author:
      -
        ins: J. Alwen
        name: Joël Alwen
        org: Wickr
      -
        ins: B. Blanchet
        name: Bruno Blanchet
        org: Inria Paris
      -
        ins: E. Hauck
        name: Eduard Hauck
        org: Ruhr-Universität Bochum
      -
        ins: E. Kiltz
        name: Eike Kiltz
        org: Ruhr-Universität Bochum
      -
        ins: B. Lipp
        name: Benjamin Lipp
        org: Inria Paris
      -
        ins: D. Riepel
        name: Doreen Riepel
        org: Ruhr-Universität Bochum
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
  CDM23:
    title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
    target: https://eprint.iacr.org/2023/1933.pdf
    date: 2023
    author:
      -
        ins: C. Cremers
        name: Cas Cremers
        org: CISPA Helmholtz Center for Information Security
      -
        ins: A. Dax
        name: Alexander Dax
        org: CISPA Helmholtz Center for Information Security
      -
        ins: N. Medinger
        name: Niklas Medinger
        org: CISPA Helmholtz Center for Information Security
  FIPS202: DOI.10.6028/NIST.FIPS.202
  FIPS203: DOI.10.6028/NIST.FIPS.203
  GHP2018: https://eprint.iacr.org/2018/024.pdf
  I-D.driscoll-pqt-hybrid-terminology:
  KSMW2024:
    target: https://eprint.iacr.org/2024/1233
    title: "Binding Security of Implicitly-Rejecting KEMs and Application to BIKE and HQC"
    author:
      -
        ins: J. Kraemer
      -
        ins: P. Struck
      -
        ins: M. Weishaupl
  LUCKY13:
    target: https://ieeexplore.ieee.org/iel7/6547086/6547088/06547131.pdf
    title: "Lucky Thirteen: Breaking the TLS and DTLS record protocols"
    author:
    -
      ins: N. J. Al Fardan
    -
      ins: K. G. Paterson
  RACCOON:
    target: https://raccoon-attack.com/
    title: "Raccoon Attack: Finding and Exploiting Most-Significant-Bit-Oracles in TLS-DH(E)"
    author:
    -
      ins: R. Merget
    -
      ins: M. Brinkmann
    -
      ins: N. Aviram
    -
      ins: J. Somorovsky
    -
      ins: J. Mittmann
    -
      ins: J. Schwenk
    date: 2020-09
  HKDF: RFC5869
  HPKE: RFC9180
  SCHMIEG2024:
    title: "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"
    target: https://eprint.iacr.org/2024/523.pdf
    date: 2024
    author:
      -
        ins: S. Schmieg
        name: Sophie Schmieg
  XWING: https://eprint.iacr.org/2024/039.pdf
  XWING-EC-PROOF: https://github.com/formosa-crypto/formosa-x-wing/

--- abstract

This document defines generic techniques to achive hybrid
post-quantum/traditional (PQ/T) key encapsulation mechanisms (KEMs) from
post-quantum and traditional component algorithms that meet specified
security properties.

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

# Requirements Notation

{::boilerplate bcp14-tagged}

# Notation

This document is consistent with all terminology defined in
{{I-D.driscoll-pqt-hybrid-terminology}}.

The following terms are used throughout this document:

- `random(n)`: return a pseudorandom byte string of length `n` bytes produced
  by a cryptographically-secure random number generator.
- `concat(x0, ..., xN)`: Concatenation of byte strings.  `concat(0x01,
  0x0203, 0x040506) = 0x010203040506`.
- `I2OSP(n, w)`: Convert non-negative integer `n` to a `w`-length, big-endian
  byte string, as described in {{!RFC8017}}.
- `OS2IP(x)`: Convert byte string `x` to a non-negative integer, as described
  in {{!RFC8017}}, assuming big-endian byte order.

## Key encapsulation mechanisms {#kems}

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

# Cryptographic Dependencies {#cryptographic-deps}

The generic hybrid PQ/T KEM constructions we define depend on the the
following cryptographic primitives:

- Post-Quantum-secure KEM {{pq-kem}
- Nominal Diffie-Hellman Group {{group}}
- Key Derivation Function {{kdf}}
- Extendable Output Function {{xof}}


## Post-Quantum KEM {{#pq-kem}}

An IND-CCA KEM that is resilient against post-quantum attacks.

### Post-quantum KEM ciphertext `pq_CT`

The ciphertext produced from one encapsulation from the post-quantum
component KEM.

### Post-quantum KEM public encapsulation key `pq_PK`

The public encapsulation key produced by one key generation from the
post-quantum component KEM.

### Post-quantum KEM shared secret `pq_SS`

The shared secret produced from one encapsulation/decapsulation from the
post-quantum component KEM.

### Traditional KEM ciphertext `trad_CT`

The ciphertext (or equivalent) produced from one encapsulation from the
traditional component KEM. For the constructions in this document, this is a
Diffie-Hellman group element.

### Traditional KEM public encapsulation key `trad_PK`

The public encapsulation key produced by one key generation from the
traditional component KEM. For the constructions in this document, this is a
Diffie-Hellman group element.

### Traditional KEM shared secret `trad_SS`

The shared secret produced from one encapsulation/decapsulation from the
traditional component KEM. For the constructions in this document, this is a
Diffie-Hellman group element.


## Key Derivation Function `KDF` {#kdf}

A secure key derivation function (KDF) that is modeled as a secure
pseudorandom function (PRF) in the [standard model][GHP2018] and independent
random oracle in the random oracle model (ROM).

## XOF {#xof}

Extendable-output function (XOF). A function on bit strings in which the
output can be extended to any desired length. Ought to satisfy the following
properties as long as the specified output length is sufficiently long to
prevent trivial attacks:

1. (One-way) It is computationally infeasible to find any input that maps to
   any new pre-specified output.

2. (Collision-resistant) It is computationally infeasible to find any two
   distinct inputs that map to the same output.

MUST provide the bit-security required to source input randomness for PQ/T
components from a seed that is expanded to a output length, of which a subset
is passed to the component key generation algorithms.

# Other

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

# Hybrid KEM Generic Constructions

## Common security requirements

### KDF as a secure PRF

A key derivation function (KDF) that is modeled as a secure pseudorandom
function (PRF) in the [standard model][GHP2018] and independent random oracle
in the random oracle model (ROM).

### IND-CCA-secure Post-Quantum KEM

A component post-quantum KEM that has IND-CCA security.

### Elliptic curve group where the Strong Diffie-Hellman problem (SDH) is hard

For these generic constructions, the traditional KEMs are [DH-KEM][RFC9180]
instantiated with a particular elliptic curve group. For one construction,
`{{QSF}}`, this requires Strong Diffie-Hellman security and to be modelable
as a nominal group.

### Fixed length

Every instantiation in concrete parameters of the generic constructions is
for fixed parameter sizes, KDF choice, and label, allowing the lengths to not
also be encoded into the generic construction. The label/KDF/component
algorithm parameter sets MUST be disjoint and non-colliding.

This document assumes and requires that the length of each public key,
ciphertext, and shared secret is fixed once the algorithm is fixed in the
concrete instantiations. This is the case for all concrete instantiations in
this document.


### X-BIND-K-CT /


<!-- # 'Chempat' construction -->

<!-- NOT INCLUDED BECAUSE NO SECURITY PROOF -->

## Key Generation {#keygen}

We specify a common generic key generation scheme for all generic
constructions. This requires the component key generation algorithns to
accept the sufficient random seed, possibly according to their parameter set.

A keypair (decapsulation key, encapsulation key) is generated as
follows.

~~~
def expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 96)
  (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
  sk_X = expanded[64:96]
  pk_X = X25519(sk_X, X25519_BASE)
  return (sk_M, sk_X, pk_M, pk_X)

def GenerateKeyPair():
  sk = random(32)
  (sk_M, sk_X, pk_M, pk_X) = expandDecapsulationKey(sk)
  return sk, concat(pk_M, pk_X)
~~~

`GenerateKeyPair()` returns the 32 byte secret decapsulation key `sk`
and the 1216 byte encapsulation key `pk`.

Here and in the balance of the document for clarity we use
the `M` and `X`subscripts for ML-KEM-768 and X25519 components respectively.

### Key derivation {#derive-key-pair}

For testing, it is convenient to have a deterministic version
of key generation. An X-Wing implementation MAY provide the following
derandomized variant of key generation.

~~~
def GenerateKeyPairDerand(sk):
  sk_M, sk_X, pk_M, pk_X = expandDecapsulationKey(sk)
  return sk, concat(pk_M, pk_X)
~~~

`sk` must be 32 bytes.

`GenerateKeyPairDerand()` returns the 32 byte secret encapsulation key
`sk` and the 1216 byte decapsulation key `pk`.


## 'Kitchen Sink' construction:

As indicated by the name, the `KitchenSink` construction puts 'the whole
transcript' through the KDF. This relies on the minimum security properties
of its component algorithms at the cost of more bytes needing to be processed
by the KDF.

~~~
def KitchenSink-KEM.SharedSecret():
    return KDF(concat(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT, trad_PK, label))
~~~

### Security properties

Because the entire hybrid KEM ciphertext and encapsulation key material are
included in the KDF preimage, the `KitchenSink` construction is resilient
against implementation errors in the component algorithms. <!-- TODO: cite
that thing -->


## 'QSF' construction {#qsf}

Inspired by the generic QSF[^qsf] framework in [XWING], which leverages the
security properties of a KEM like ML-KEM and an inlined instance of DH-KEM,
to elide other public data like the PQ ciphertext and encapsulation key from
the KDF input:

[qsf] Quantum Superiority Fighter

~~~
def QSF-KEM.SharedSecret():
    return KDF(concat(pq_SS, trad_SS, trad_CT, trad_PK, label))
~~~

### Requirements

#### Nominal Diffie-Hellman Group with strong Diffie-Hellman security {#group}

A cryptographic group modelable as a nominal group where the strong
Diffie-Hellman assumption holds {XWING}. Specically regarding a nominal
group, this means that especially the {{QSF}} construction's security is
based on a computational-Diffie-Hellman-like problem, but no assumption is
made about the format of the generated group element - no assumption is made
that the shared group element is indistinguishable from random bytes.

The concrete instantiations in this document use elliptic curve groups that
have been modeled as nominal groups in the literature.

#### Post-quantum IND-CCA KEM with ciphertext second preimage resistance

The QSF relies the post-quantum KEM component having IND-CCA security against
a post-quantum attacker, and ciphertext second preimage resistance (C2SPI,
also known as chosen ciphertext resistance, CCR). C2SPI/CCR is [equivalent to
LEAK-BIND-K,PK-CT security][CDM23]


#### KDF is a secure (post-quantum) PRF, modelable as a random oracle

Indistinguishability of the final shared secret from a random key is
established by modeling the key-derivation function as a random
oracle. {{XWING}}


# Concrete Hybrid KEM Instances


## `QSF-SHA3-256-ML-KEM-768-P-256`

### Security properties


#### Binding

The inlined DH-KEM is instantiated over the elliptic curve group P-256: as
shown in {{CDM2023}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-768 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}.

Therefore this concrete instance provides MAL-BIND-K-PK and MAL-BIND-K-CT
security. <!-- TODO: update XWING paper to show this -->

This implies via {{KSMW}} that this instance also satisfies

- MAL-BIND-K,CT-PK
- MAL-BIND-K,PK-CT
- LEAK-BIND-K-PK
- LEAK-BIND-K-CT
- LEAK-BIND-K,CT-PK
- LEAK-BIND-K,PK-CT
- HON-BIND-K-PK
- HON-BIND-K-CT
- HON-BIND-K,CT-PK
- HON-BIND-K,PK-CT

## `KitchenSink-HKDF-SHA-256-ML-KEM-768-X25519`

#### Binding

The inlined DH-KEM instantiated over the elliptic curve group X25519: as
shown in {{CDM2023}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-768 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}. Further, the ML-KEM ciphertext
and encapsulation key are included in the KDF preimage, giving
straightforward CT and PK binding for the entire bytes of the hybrid KEM
ciphertext and encapsulation key. Therefore this concrete instance provides
MAL-BIND-K-PK and MAL-BIND-K-CT security.

This implies via {{KSMW}} that this instance also satisfies

- MAL-BIND-K,CT-PK
- MAL-BIND-K,PK-CT
- LEAK-BIND-K-PK
- LEAK-BIND-K-CT
- LEAK-BIND-K,CT-PK
- LEAK-BIND-K,PK-CT
- HON-BIND-K-PK
- HON-BIND-K-CT
- HON-BIND-K,CT-PK
- HON-BIND-K,PK-CT

## `QSF-SHA3-256-ML-KEM-1024-P-384`

#### Binding

The inlined DH-KEM is instantiated over the elliptic curve group P-384: as
shown in {{CDM2023}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-1024 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}.

Therefore this concrete instance provides MAL-BIND-K-PK and MAL-BIND-K-CT
security. <!-- TODO: update XWING paper to show this -->

This implies via {{KSMW}} that this instance also satisfies

- MAL-BIND-K,CT-PK
- MAL-BIND-K,PK-CT
- LEAK-BIND-K-PK
- LEAK-BIND-K-CT
- LEAK-BIND-K,CT-PK
- LEAK-BIND-K,PK-CT
- HON-BIND-K-PK
- HON-BIND-K-CT
- HON-BIND-K,CT-PK
- HON-BIND-K,PK-CT


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

## Other Component Primitives

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
