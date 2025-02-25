---
title: "Hybrid PQ/T Key Encapsulation Mechanisms"
abbrev: hybrid-kems
category: info

docname: draft-irtf-cfrg-hybrid-kems-latest
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
  FIPS202: DOI.10.6028/NIST.FIPS.202
  FIPS203: DOI.10.6028/NIST.FIPS.203

informative:
  ANSIX9.62:
    title: "Public Key Cryptography for the Financial Services Industry: the Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: Nov, 2005
    seriesinfo:
      "ANS": X9.62-2005
    author:
      -
        org: ANS
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
  BDG2020:
    title: "Separate Your Domains: NIST PQC KEMs, Oracle Cloning and Read-Only Indifferentiability"
    target: https://eprint.iacr.org/2020/241.pdf
    date: 2020
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
  FIPS186: DOI.10.6028/NIST.FIPS.186-5 #https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
  GHP2018:
    title: "KEM Combiners"
    target: https://eprint.iacr.org/2018/024.pdf
    date: 2018
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
  SCHMIEG2024:
    title: "Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK"
    target: https://eprint.iacr.org/2024/523.pdf
    date: 2024
    author:
      -
        ins: S. Schmieg
        name: Sophie Schmieg
  SEC1:
    title: "Elliptic Curve Cryptography, Standards for Efficient Cryptography Group, ver. 2"
    target: https://secg.org/sec1-v2.pdf
    date: 2009
  XWING:
    title: "X-Wing: The Hybrid KEM You’ve Been Looking For"
    target: https://eprint.iacr.org/2024/039.pdf
    date: 2024
  # XWING-EC-PROOF: https://github.com/formosa-crypto/formosa-x-wing/

--- abstract

This document defines generic techniques to achive hybrid
post-quantum/traditional (PQ/T) key encapsulation mechanisms (KEMs) from
post-quantum and traditional component algorithms that meet specified
security properties. It then uses those generic techniques to construct
several concrete instances of hybrid KEMs.

--- middle

# Introduction {#intro}

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

When `x` is a byte string, we use the notation `x[..i]` and `x[i..]` to
denote the slice of bytes in `x` starting from the beginning of `x` and
leading up to index `i`, including the `i`-th byte, and the slice the bytes
in `x` starting from index `i` to the end of `x`, respectively. For example,
if `x = [0, 1, 2, 3]`, then `x[..2] = [0, 1]` and `x[2..] = [2, 3]`.

# Cryptographic Dependencies {#cryptographic-deps}

The generic hybrid PQ/T KEM constructions we define depend on the the
following cryptographic primitives:

- Key Encapsulation Mechanism {{kems}};
- Extendable Output Function (XOF) {{xof}};
- Key Derivation Function (KDF) {{kdf}}; and
- Nominal Diffie-Hellman Group {{group}}.

These dependencies are defined in the following subsections.

## Key encapsulation mechanisms {#kems}

Key encapsulation mechanisms (KEMs) are cryptographic schemes that consist of
four algorithms:

- `KeyGen() -> (pk, sk)`: A probabilistic key generation algorithm, which
  generates a public encapsulation key `pk` and a secret decapsulation key
  `sk`, each of which are byte strings.
- `DeriveKey(seed) -> (pk, sk)`: A deterministic algorithm, which takes as
  input a seed `seed` and generates a public encapsulation key `pk` and a
  secret decapsulation key `sk`, each of which are byte strings.
- `Encaps(pk) -> (ct, shared_secret)`: A probabilistic encapsulation
  algorithm, which takes as input a public encapsulation key `pk` and outputs
  a ciphertext `ct` and shared secret `shared_secret`.
- `Decaps(sk, ct) -> shared_secret`: A decapsulation algorithm, which takes
  as input a secret decapsulation key `sk` and ciphertext `ct` and outputs a
  shared secret `shared_secret`.

KEMs can also provide a deterministic version of `Encaps`, denoted
`EncapsDerand`, with the following signature:

- `EncapsDerand(pk, randomness) -> (ct, shared_secret)`: A deterministic
   encapsulation algorithm, which takes as input a public encapsulation key
   `pk` and randomness `randomness`, and outputs a ciphertext `ct` and shared
   secret `shared_secret`.

Finally, KEMs are also parameterized with the following constants:

- Nseed, which denotes the number of bytes for a key seed;
- Npk, which denotes the number of bytes in a public encapsulation key;
- Nsk, which denotes the number of bytes in a private decapsulation key; and
- Nct, which denotes the number of bytes in a ciphertext.

## `XOF` {#xof}

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

## Key Derivation Function `KDF` {#kdf}

A secure key derivation function (KDF) that is modeled as a secure
pseudorandom function (PRF) in the standard model {{GHP2018}} and independent
random oracle in the random oracle model (ROM).

## Nominal Diffie-Hellman Group {#group}

The traditional DH-KEM construction depends on an abelian group of order
`order`. We represent this group as the object `G` that additionally defines
helper functions described below. The group operation for `G` is addition `+`
with identity element `I`. For any elements `A` and `B` of the group `G`,
`A + B = B + A` is also a member of `G`. Also, for any `A` in `G`, there
exists an element `-A` such that `A + (-A) = (-A) + A = I`. For convenience,
we use `-` to denote subtraction, e.g., `A - B = A + (-B)`.  Integers, taken
modulo the group order `order`, are called scalars; arithmetic operations on
scalars are implicitly performed modulo `order`. Scalar multiplication is
equivalent to the repeated application of the group operation on an element
`A` with itself `r-1` times, denoted as `ScalarMult(A, r)`. We denote the
sum, difference, and product of two scalars using the `+`, `-`, and `*`
operators, respectively. (Note that this means `+` may refer to group element
addition or scalar addition, depending on the type of the operands.) For any
element `A`, `ScalarMult(A, order) = I`.  We denote `B` as a fixed generator
of the group. Scalar base multiplication is equivalent to the repeated
application of the group operation on `B` with itself `r-1` times, this is
denoted as `ScalarBaseMult(r)`. The set of scalars corresponds to
`GF(order)`, which we refer to as the scalar field. It is assumed that group
element addition, negation, and equality comparison can be efficiently
computed for arbitrary group elements.

This document uses types `Element` and `Scalar` to denote elements of the
group `G` and its set of scalars, respectively. We denote `Scalar(x)` as the
conversion of integer input `x` to the corresponding `Scalar` value with the
same numeric value. For example, `Scalar(1)` yields a `Scalar` representing
the value 1.  We denote equality comparison of these types as `==` and
assignment of values by `=`. When comparing Scalar values, e.g., for the
purposes of sorting lists of Scalar values, the least nonnegative
representation mod `order` is used.

We now detail a number of member functions that can be invoked on `G`.

- Order(): Outputs the order of `G` (i.e., `order`).
- Identity(): Outputs the identity `Element` of the group (i.e., `I`).
- RandomScalar(): Outputs a random `Scalar` element in GF(order), i.e., a
  random scalar in \[0, order - 1\].
- ScalarMult(A, k): Outputs the scalar multiplication between Element `A` and
  Scalar `k`.
- ScalarBaseMult(k): Outputs the scalar multiplication between Scalar `k` and
  the group generator `B`.
- SerializeElementAsSharedSecret(A): Maps an `Element` `A` to a fixed-length byte
  array. This function is used to produce a shared secret for Diffie-Hellman
  operations performed on the group.
- SerializeElement(A): Maps an `Element` `A` to a canonical byte array `buf`
  of fixed length `Ne`. This function raises an error if `A` is the identity
  element of the group.
- DeserializeElement(buf): Attempts to map a byte array `buf` to an `Element`
  `A`, and fails if the input is not the valid canonical byte representation
  of an element of the group. This function raises an error if
  deserialization fails or if `A` is the identity element of the group.
- SerializeScalar(s): Maps a Scalar `s` to a canonical byte array `buf` of
  fixed length `Ns`.
- DeserializeScalar(buf): Attempts to map a byte array `buf` to a `Scalar`
  `s`.  This function raises an error if deserialization fails.
- ScalarFromBytes(buf): Maps a byte array `buf` to a `Scalar` by first
  interpreting the contents of `buf` as an unsigned integer and then
  reducing that integer modulo the group order; this ensures that the
  resulting integer is always an element of the Scalar field.

# Hybrid KEM Constructions {#constructions}

<!-- TODO: since NIST is OK'ing ML-KEM keygen from a NIST-approved KDF/PRF,
specify the generic seed-stretching KeyGen for all/both constructions,
here. -->

During encapsulation and decapsulation, a hybrid KEM combines its component
KEM shared secrets and other info, such as the KEM ciphertexts and
encapsulation keys keys, to yield a shared secret.  The interface for this
function, often called a 'combiner' in the literature, is the `SharedSecret`
function for the constructions in this document. `SharedSecret` accepts the
following inputs:

- pq_SS: The PQ KEM shared secret.
- trad_SS: The traditional KEM shared secret.
- pq_CT: The PQ KEM ciphertext.
- pq_PK: The PQ KEM public encapsulation key.
- trad_CT: The traditional KEM ciphertext.
- trad_PK: The traditional KEM public encapsulation key.
- label: A domain-separating label; see {{domain-separation}} for more
  information on the role of the label.

The output of the `SharedSecret` function is a 32 byte shared secret that is,
ultimately, the output of the KEM. <!-- TODO: this doesn't hold generically,
right? If you instantiate with other components it can be more or less than
32 bytes. -->

This section describes two generic constructions for hybrid KEMs: one called
the KitchenSink, specified in {{KitchenSink}}, and another called QSF,
specified in {{QSF}}.  The KitchenSink construction is maximally conservative
in design, opting for the least assumptions about the component KEMs. The QSF
construction is tailored to specific component KEMs and is not generally
reusable; specific requirements for component KEMs to be usable in the QSF
combiner are detailed in {{QSF}}.

Both make use of the following requirements:

1. Both component KEMs have IND-CCA security.
2. KDF as a secure PRF. A key derivation function (KDF) that is modeled as a
secure pseudorandom function (PRF) in the standard model {{GHP2018}} and
independent random oracle in the random oracle model (ROM).
3. Fixed-length values. Every instantiation in concrete parameters of the
generic constructions is for fixed parameter sizes, KDF choice, and label,
allowing the lengths to not also be encoded into the generic
construction. The label/KDF/component algorithm parameter sets MUST be
disjoint and non-colliding. Moreover, the length of each each public
encapsulation key, ciphertext, and shared secret is fixed once the algorithm
is assumed to be fixed.

## Key generation and derivation {#generic-keygen}

For both constructions in this document we provide a common key generation
and derivation design. It relies on the following parameters that are
populated by concrete instantiations:

* `XOF`: the eXtended Output Function
* `PQKEM`: the PQ KEM component scheme
* `G`: the nomimal group used to construct the traditional KEM component
  scheme as described in {{group}
* Nseed: length in bytes of the seed randomness sourced from the RNG
* Npqseed: length in bytes of the input to PQ.DeriveKey()
* Ntradseed: length in bytes of the input to NominalGroup.ScalarFromBytes()

~~~
def expandDecapsulationKey(sk):
  expanded = XOF(sk, Npqseed + Ntradseed)
  (pq_PK, pq_SK) = PQKEM.DeriveKey(expanded[..Npqseed])
  trad_SK = G.ScalarFromBytes(expanded[Npqseed..])
  trad_PK = G.SerializeElement(NominalGroup.ScalarMultBase(trad_SK))
  return (pq_SK, trad_SK, pq_PK, trad_PK)

def KeyGen():
  sk = random(Nseed)
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  return sk, concat(pq_PK, trad_PK)
~~~

Similarly, `DeriveKey` works as follows:

~~~
def DeriveKey(seed):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(seed)
  return sk, concat(pq_PK, trad_PK)
~~~


## 'Kitchen Sink' construction {#KitchenSink}

As indicated by the name, the `KitchenSink` puts 'the whole transcript'
through the KDF. This relies on the minimum security properties of its
component algorithms at the cost of more bytes needing to be processed by the
KDF.

~~~
def KitchenSink-KEM.SharedSecret(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT,
                                 trad_PK, label):
    input = concat(pq_SS, trad_SS, pq_CT, pq_PK,
                   trad_CT, trad_PK, label)
    return KDF(input)
~~~

### Security properties

Because the entire hybrid KEM ciphertext and encapsulation key material are
included in the KDF preimage, the `KitchenSink` construction is resilient
against implementation errors in the component algorithms. <!-- TODO: cite
that thing -->

## 'QSF' construction {#QSF}

Inspired by the generic QSF (Quantum Superiority Fighter) framework in
{{XWING}}, which leverages the security properties of a KEM like ML-KEM and
an inlined instance of DH-KEM, to elide other public data like the PQ
ciphertext and encapsulation key from the KDF input:

~~~
def QSF-KEM.SharedSecret(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT,
                         trad_PK, label):
    return KDF(concat(pq_SS, trad_SS, trad_CT, trad_PK, label))
~~~

Note that pq_CT and pq_PK are NOT included in the KDF. This is only possible
because the component KEMs adhere to the following requirements. The QSF
combiner MUST NOT be used in concrete KEM instances that do not satisfy these
requirements.

1. Nominal Diffie-Hellman Group with strong Diffie-Hellman security

A cryptographic group modelable as a nominal group where the strong
Diffie-Hellman assumption holds {XWING}. Specically regarding a nominal
group, this means that especially the QSF construction's security is
based on a computational-Diffie-Hellman-like problem, but no assumption is
made about the format of the generated group element - no assumption is made
that the shared group element is indistinguishable from random bytes.

The concrete instantiations in this document use elliptic curve groups that
have been modeled as nominal groups in the literature.

2. Post-quantum IND-CCA KEM with ciphertext second preimage resistance

The QSF relies the post-quantum KEM component having IND-CCA security against
a post-quantum attacker, and ciphertext second preimage resistance (C2SPI,
also known as chosen ciphertext resistance, CCR). C2SPI/CCR is [equivalent to
LEAK-BIND-K,PK-CT security][CDM23]

3. KDF is a secure (post-quantum) PRF, modelable as a random oracle.

Indistinguishability of the final shared secret from a random key is
established by modeling the key-derivation function as a random
oracle {{XWING}}.


# Concrete Hybrid KEM Instances

This section instantiates three concrete KEMs:

1. `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` {{qsf-p256}}:
   A hybrid KEM using the QSF combiner with SHA3-256 as the hash function
   based on ML-KEM-768 and P-256, along with SHAKE256 as the key derivation XOF.
2. `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` {{ks-x25519}}:
   A hybrid KEM using the KitchenSink combiner based on ML-KEM-768 and X25519.
3. `QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` {{qsf-p384}}:
   A hybrid KEM using the QSF combiner with SHA3-256 as the hash function
   based on ML-KEM-1024 and P-384, along with SHAKE256 as the key derivation XOF.

Each instance specifies the PQ and traditional KEMs being combined, the
combiner construction from {{constructions}}, the `label` to use for domain
separation in the combiner function, as well as the XOF and KDF functions to
use throughout.

## `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` {#qsf-p256}

This hybrid KEM is heavily based on {{XWING}}. In particular, it has the same
exact design but uses P-256 instead of X25519 as the the traditional
component of the algorithm. It has the following parameters.

* `label`: `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)`
* `XOF`: SHAKE-256 {{FIPS202}}
* `KDF`: SHA3-256 {{FIPS202}}
* Combiner: QSF-KEM.SharedSecret
* Nseed: 32
* Npqseed: 64
* Ntradseed: 48
* Npk: 1217
* Nsk: 32
* Nct: 1121

`QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` depends on P-256 as a nominal prime-order
group {{FIPS186}} (secp256r1) {{ANSIX9.62}}, where Ne = 33 and Ns = 32, with
the following functions:

- Order(): Return
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551.
- Identity(): As defined in {{ANSIX9.62}}.
- RandomScalar(): Implemented by returning a uniformly random Scalar in the
  range \[0, `G.Order()` - 1\]. Refer to {{random-scalar}} for
  implementation guidance.
- SerializeElement(A): Implemented using the compressed
  Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}},
  yielding a 33-byte output. Additionally, this function validates that the
  input element is not the group identity element.
- DeserializeElement(buf): Implemented by attempting to deserialize a
  33-byte input string to a public key using the compressed
  Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}}, and
  then performs public-key validation as defined in section 3.2.2.1 of
  {{SEC1}}.  This includes checking that the coordinates of the resulting
  point are in the correct range, that the point is on the curve, and that
  the point is not the point at infinity. (As noted in the specification,
  validation of the point order is not required since the cofactor is 1.)
  If any of these checks fail, deserialization returns an error.
- SerializeElementAsSharedSecret(A): Implemented by encoding the X coordinate
  of the elliptic curve point corresponding to A to a little-endian 32-byte string.
- SerializeScalar(s): Implemented using the Field-Element-to-Octet-String
  conversion according to {{SEC1}}.
- DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar
  from a 32-byte string using Octet-String-to-Field-Element from
  {{SEC1}}. This function can fail if the input does not represent a Scalar
  in the range \[0, `G.Order()` - 1\].
- ScalarFromBytes(buf): Implemented by converting `buf` to an integer using
  OS2IP, and then reducing the resulting integer modulo the group order.

The rest of this section specifies the key generation, encapsulation, and
decapsulation procedures for this hybrid KEM.

### Key generation

`QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` KeyGen works as follows.

<!-- TODO: is this expanding from a decaps key seed, but maybe this should
just be 'expandKeyPair` -->

<!-- TODO: annotate with the byte sizes of the parameters in terms of Nseed,
Nsk, etc -->

~~~
def expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 112)
  (pq_PK, pq_SK) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
  trad_SK = P-256.ScalarFromBytes(expanded[64:112])
  trad_PK = P-256.SerializeElement(P-256.ScalarMultBase(trad_SK))
  return (pq_SK, trad_SK, pq_PK, trad_PK)

def KeyGen():
  sk = random(32)
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  return sk, concat(pq_PK, trad_PK)
~~~

Similarly, `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` DeriveKey works as follows:

~~~
def DeriveKey(seed):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(seed)
  return sk, concat(pq_PK, trad_PK)
~~~

### Encapsulation

Given an encapsulation key `pk`, `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` Encaps
proceeds as follows.

~~~
def Encaps(pk):
  pq_PK = pk[0:1184]
  trad_PK = P-256.DeserializeElement(pk[1184:1217])
  (pq_SS, pq_CT) = ML-KEM-768.Encaps(pq_PK)
  ek = P-256.RandomScalar()
  trad_CT = P-256.SerializeElement(P-256.ScalarBaseMult(ek))
  trad_SS = P-256.SerializeElementAsSharedSecret(P-256.ScalarMult(trad_PK, ek))
  ss = SHA3-256(pq_SS, trad_SS, trad_CT, pk[1184:1217], label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

`pk` is a 1217-byte encapsulation key resulting from KeyGen().

Encaps() returns the 32-byte shared secret `ss` and the 1121-byte ciphertext
`ct`.

Note that `Encaps()` may raise an error if ML-KEM-768.Encaps fails, e.g., if
it does not pass the check of {{FIPS203}} §7.2.

### Derandomized

For testing, it is convenient to have a deterministic version of
encapsulation. In such cases, an implementation can provide the following
derandomized function.

~~~
def EncapsDerand(pk, randomness):
  pq_PK = pk[0:1184]
  trad_PK = P-256.DeserializeElement(pk[1184:1217])
  (pq_SS, pq_CT) = ML-KEM-768.EncapsDerand(pq_PK, randomness[0:32])
  ek = P-256.ScalarFromBytes(randomness[32:80])
  trad_CT = P-256.SerializeElement(P-256.ScalarMultBase(ek))
  trad_SS = P-256.SerializeElementAsSharedSecret(P-256.ScalarMult(ek, trad_PK))
  ss = SHA3-256(pq_SS, trad_SS, trad_CT, trad_PK, label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

Note that `randomness` MUST be 80 bytes.

### Decapsulation

Given a decapsulation key `sk` and ciphertext `ct`,
`QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)` Decaps proceeds as follows.

~~~
def Decaps(sk, ct):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  pq_CT = ct[0:1088]
  trad_CT = P-256.DeserializeElement(ct[1088:1121])
  pq_SS = ML-KEM-768.Decapsulate(pq_SK, pq_CT)
  trad_SS = P-256.SerializeElementAsSharedSecret(P-256.ScalarMult(trad_SK, trad_CT))
  return SHA3-256(pq_SS, trad_SS, ct[1088:1121], trad_PK, label)
~~~

`ct` is the 1121-byte ciphertext resulting from Encaps() and `sk` is a
32-byte decapsulation key resulting from KeyGen().

Decaps() returns the 32 byte shared secret.

### Security properties

The inlined DH-KEM is instantiated over the elliptic curve group P-256: as
shown in {{CDM23}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-768 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}}.

Therefore this concrete instance provides MAL-BIND-K-PK and MAL-BIND-K-CT
security. <!-- TODO: update XWING paper to show this -->

This implies via {{KSMW2024}} that this instance also satisfies

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

## `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` {#ks-x25519}

KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256) has the following parameters.

* `label`: `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)`
* `XOF`: SHAKE-256 {{FIPS202}}
* `KDF`: HKDF-SHA-256 {{HKDF}}
* Combiner: KitchenSink-KEM.SharedSecret
* Nseed: 32
* Npqseed: 64
* Ntradseed: 32
* Npk: 1216
* Nsk: 32
* Nct: 1120

`KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` depends on a prime-order group
implemented using Curve25519 and X25519 {{!RFC7748}}. Additionally, it uses a
modified version of HKDF in the combiner, denoted LabeledHKDF, defined below.

<!-- TODO: double check on whether the public context should go in `*_info`
or if all concatted is fine; i think a separate label is ok? HKDF as a split
PRF seems extra?-->

~~~
def LabeledExtract(salt, label, ikm):
  labeled_ikm = concat(label, ikm)
  return HDKF-Extract(salt, labeled_ikm)

def LabeledExpand(prk, label, info, L):
  labeled_info = concat(I2OSP(L, 2), label, info)
  return HKDF-Expand(prk, labeled_info, L)

def LabeledHKDF(preimage):
  prk = LabeledExtract("", "hybrid_prk", preimage)
  shared_secret = LabeledExpand(prk, "shared_secret", "", 32)
  return shared_secret
~~~

The rest of this section specifies the key generation, encapsulation, and
decapsulation procedures for this hybrid KEM.

### Key generation

`KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` KeyGen works as follows.

~~~
def expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 96)
  (pq_PK, pq_SK) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
  trad_SK = expanded[64:96]
  trad_PK = X25519(trad_SK, 9)
  return (pq_SK, trad_SK, pq_PK, trad_PK)

def KeyGen():
  sk = random(32)
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  return sk, concat(pq_PK, trad_PK)
~~~

Similarly, `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` DeriveKey works as
follows:

~~~
def DeriveKey(seed):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(seed)
  return sk, concat(pq_PK, trad_PK)
~~~

### Encapsulation

Given an encapsulation key `pk`, `KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)`
Encaps proceeds as follows.

~~~
def Encaps(pk):
  pq_PK = pk[0:1184]
  trad_PK = pk[1184:1216]
  (pq_SS, pq_CT) = ML-KEM-768.Encaps(pq_PK)
  ek = random(32)
  trad_CT = X25519(ek, 9)
  trad_SS = X25519(ek, trad_PK)
  ss = LabeledHKDF(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT, trad_PK, label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

`pk` is a 1216-byte encapsulation key resulting from KeyGen().

Encaps() returns the 32-byte shared secret ss and the 1120-byte ciphertext
ct.

Note that `Encaps()` may raise an error if ML-KEM-768.Encaps fails, e.g., if
it does not pass the check of {{FIPS203}} §7.2.

### Derandomized

For testing, it is convenient to have a deterministic version of
encapsulation. In such cases, an implementation can provide the following
derandomized function.

~~~
def EncapsDerand(pk, randomness):
  pq_PK = pk[0:1184]
  trad_PK = pk[1184:1216]
  (pq_SS, pq_CT) = PQ-KEM.EncapsDerand(pq_PK, randomness[0:32])
  ek = randomness[32:64]
  trad_CT = X25519(ek, 9)
  trad_SS = X25519(ek, trad_PK)
  ss = LabeledHKDF(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT, trad_PK, label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

Note that `randomness` MUST be 64 bytes.

### Decapsulation

Given a decapsulation key `sk` and ciphertext `ct`,
`KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)` Decaps proceeds as follows.

~~~
def Decaps(sk, ct):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  pq_CT = ct[0:1088]
  trad_CT = ct[1088:1120]
  pq_SS = ML-KEM-768.Decapsulate(pq_SK, pq_CT)
  trad_SS = X25519(trad_SK, trad_CT)
  return LabeledHKDF(pq_SS, trad_SS, pq_CT, pq_PK, trad_CT, trad_PK, label)
~~~

`ct` is the 1120-byte ciphertext resulting from Encaps() and `sk` is a
32-byte decapsulation key resulting from KeyGen().

Decaps() returns the 32 byte shared secret.

### Security properties

The inlined DH-KEM instantiated over the elliptic curve group X25519: as
shown in {{CDM23}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-768 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}}. Further, the ML-KEM ciphertext
and encapsulation key are included in the KDF preimage, giving
straightforward CT and PK binding for the entire bytes of the hybrid KEM
ciphertext and encapsulation key. Therefore this concrete instance provides
MAL-BIND-K-PK and MAL-BIND-K-CT security.

This implies via {{KSMW2024}} that this instance also satisfies

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

## `QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` {#qsf-p384}

<!-- TODO: include the XOF in the name?? -->

`QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` has the following parameters.

* `label`: `QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)`
* `XOF`: SHAKE-256 {{FIPS202}}
* `KDF`: SHA3-256 {{FIPS202}}
* Combiner: QSF-KEM.SharedSecret
* Nseed: 32
* Npqseed: 64
* Ntradseed: 72
* Npk: 1629
* Nsk: 32
* Nct: 1629

`QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` depends on P-384 as a nominal prime-order
group {{FIPS186}} (secp256r1) {{ANSIX9.62}}, where Ne = 61 and Ns = 48, with
the following functions:

- Order(): Return
  0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf
  581a0db248b0a77aecec196accc52973
- Identity(): As defined in {{ANSIX9.62}}.
- RandomScalar(): Implemented by returning a uniformly random Scalar in the
  range \[0, `G.Order()` - 1\]. Refer to {{random-scalar}} for
  implementation guidance.
- SerializeElement(A): Implemented using the compressed
  Elliptic-Curve-Point-to-Octet-String method according to {{SEC1}}, yielding
  a 61-byte output. Additionally, this function validates that the input
  element is not the group identity element.
- DeserializeElement(buf): Implemented by attempting to deserialize a 61-byte
  input string to a public key using the compressed
  Octet-String-to-Elliptic-Curve-Point method according to {{SEC1}}, and then
  performs public-key validation as defined in section 3.2.2.1 of {{SEC1}}.
  This includes checking that the coordinates of the resulting point are in
  the correct range, that the point is on the curve, and that the point is
  not the point at infinity. (As noted in the specification, validation of
  the point order is not required since the cofactor is 1.)  If any of these
  checks fail, deserialization returns an error.
- SerializeElementAsSharedSecret(A): Implemented by encoding the X coordinate
  of the elliptic curve point corresponding to A to a little-endian 48-byte
  string.
- SerializeScalar(s): Implemented using the Field-Element-to-Octet-String
  conversion according to {{SEC1}}.
- DeserializeScalar(buf): Implemented by attempting to deserialize a Scalar
  from a 48-byte string using Octet-String-to-Field-Element from
  {{SEC1}}. This function can fail if the input does not represent a Scalar
  in the range \[0, `G.Order()` - 1\].
- ScalarFromBytes(buf): Implemented by converting `buf` to an integer using
  OS2IP, and then reducing the resulting integer modulo the group order.

The rest of this section specifies the key generation, encapsulation, and
decapsulation procedures for this hybrid KEM.

### Key generation

`QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` KeyGen works as follows.

~~~
def expandDecapsulationKey(sk):
  expanded = SHAKE256(sk, 136)
  (pq_PK, pq_SK) = ML-KEM-1024.KeyGen_internal(expanded[0:32], expanded[32:64])
  trad_SK = P-384.ScalarFromBytes(expanded[64:136])
  trad_PK = P-384.SerializeElement(P-384.ScalarMultBase(trad_SK))
  return (pq_SK, trad_SK, pq_PK, trad_PK)

def KeyGen():
  sk = random(32)
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  return sk, concat(pq_PK, trad_PK)
~~~

Similarly, `QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` DeriveKey works as follows:

~~~
def DeriveKey(seed):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(seed)
  return sk, concat(pq_PK, trad_PK)
~~~

### Encapsulation

Given an encapsulation key `pk`, `QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` Encaps
proceeds as follows.

~~~
def Encaps(pk):
  pq_PK = pk[0:1568]
  trad_PK = P-384.DeserializeElement(pk[1568:1629])
  (pq_SS, pq_CT) = ML-KEM-1024.Encaps(pq_PK)
  ek = P-384.RandomScalar()
  trad_CT = P-384.SerializeElement(P-384.ScalarBaseMult(ek))
  trad_SS = P-384.SerializeElementAsSharedSecret(P-384.ScalarMult(trad_PK, ek))
  ss = SHA3-256(pq_SS, trad_SS, trad_CT, pk[1568:1629], label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

`pk` is a 1629-byte encapsulation key resulting from KeyGen().

Encaps() returns the 32-byte shared secret `ss` and the 1629-byte ciphertext
`ct`.

Note that `Encaps()` may raise an error if ML-KEM-1024.Encaps fails, e.g., if
it does not pass the check of {{FIPS203}} §7.2.

### Derandomized

For testing, it is convenient to have a deterministic version of
encapsulation. In such cases, an implementation can provide the following
derandomized function.

~~~
def EncapsDerand(pk, randomness):
  pq_PK = pk[0:1568]
  trad_PK = P-384.DeserializeElement(pk[1568:1629])
  (pq_SS, pq_CT) = ML-KEM-1024.EncapsDerand(pq_PK, randomness[0:32])
  ek = P-384.ScalarFromBytes(randomness[32:80])
  trad_CT = P-384.SerializeElement(P-384.ScalarMultBase(ek))
  trad_SS = P-384.SerializeElementAsSharedSecret(P-384.ScalarMult(ek, trad_PK))
  ss = SHA3-256(pq_SS, trad_SS, trad_CT, pk[1568:1629], label)
  ct = concat(pq_CT, trad_CT)
  return (ss, ct)
~~~

Note that `randomness` MUST be 80 bytes.

### Decapsulation

Given a decapsulation key `sk` and ciphertext `ct`,
`QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)` Decaps proceeds as follows.

~~~
def Decaps(sk, ct):
  (pq_SK, trad_SK, pq_PK, trad_PK) = expandDecapsulationKey(sk)
  pq_CT = ct[0:1568]
  trad_CT = P-384.DeserializeElement(ct[1568:1629])
  pq_SS = ML-KEM-1024.Decapsulate(pq_SK, pq_CT)
  trad_SS = P-384.SerializeElementAsSharedSecret(P-384.ScalarMult(trad_SK, trad_CT))
  return SHA3-256(pq_SS, trad_SS, ct[1568:1629], trad_PK, label)
~~~

`ct` is the 1629-byte ciphertext resulting from Encaps() and `sk` is a
32-byte decapsulation key resulting from KeyGen().

Decaps() returns the 32-byte shared secret.

### Security properties

The inlined DH-KEM is instantiated over the elliptic curve group P-384: as
shown in {{CDM23}}, this gives the traditional KEM maximum binding
properties (MAL-BIND-K-CT, MAL-BIND-K-PK).

ML-KEM-1024 as standardized in {{FIPS203}}, when using the 64-byte seed key
format as is here, provides MAL-BIND-K-CT security and LEAK-BIND-K-PK
security, as demonstrated in {{SCHMIEG2024}}.

Therefore this concrete instance provides MAL-BIND-K-PK and MAL-BIND-K-CT
security. <!-- TODO: update XWING paper to show this -->

This implies via {{KSMW2024}} that this instance also satisfies

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

# Random Scalar Generation {#random-scalar}

Two popular algorithms for generating a random integer uniformly distributed in
the range \[0, G.Order() -1\] are as follows:

## Rejection Sampling

Generate a random byte array with `Ns` bytes, and attempt to map to a Scalar
by calling `DeserializeScalar` in constant time. If it succeeds, return the
result. If it fails, try again with another random byte array, until the
procedure succeeds. Failure to implement `DeserializeScalar` in constant time
can leak information about the underlying corresponding Scalar.

As an optimization, if the group order is very close to a power of
2, it is acceptable to omit the rejection test completely.  In
particular, if the group order is p, and there is an integer b
such that |p - 2<sup>b</sup>| is less than 2<sup>(b/2)</sup>, then
`RandomScalar` can simply return a uniformly random integer of at
most b bits.

## Wide Reduction

Generate a random byte array with `l = ceil(((3 * ceil(log2(G.Order()))) / 2)
/ 8)` bytes, and interpret it as an integer; reduce the integer modulo
`G.Order()` and return the result. See {{Section 5 of !HASH-TO-CURVE=RFC9380}}
for the underlying derivation of `l`.

# Security Considerations

Hybrid KEM constructions aim to provide security by combining two or more
schemes so that security is preserved if all but one schemes are replaced by
an arbitrarily bad scheme. Informally, these hybrid KEMs are secure if the `KDF`
is secure, and either the elliptic curve is secure, or the post-quantum KEM is
secure: this is the 'hybrid' property.

More precisely for the concrete instantiations in this document, if SHA3-256,
SHA3-512, and SHAKE-256 may be modelled as a random oracle, then the IND-CCA
security of `QSF` constructions is bounded by the IND-CCA security of ML-KEM,
and the gap-CDH security of secp256n1, see {{XWING}}.

## IND-CCA security

Also known as IND-CCA2 security for general public key encryption, for KEMs
that encapsulate a new random 'message' each time.

The notion of INDistinguishability against Chosen-Ciphertext Attacks
(IND-CCA) [RS92] is now widely accepted as the standard security notion for
asymmetric encryption schemes. IND-CCA security requires that no efficient
adversary can recognize which of two messages is encrypted in a given
ciphertext, even if the two candidate messages are chosen by the adversary
himself.

## Ciphertext second preimage resistant (C2PRI) security / ciphertext collision resistance (CCR)

The notion where, even if a KEM has broken IND-CCA security (either due to
construction, implementation, or other), its internal structure, based on the
Fujisaki-Okamoto transform, guarantees that it is impossible to find a second
ciphertext that decapsulates to the same shared secret `K`: this notion is
known as ciphertext second preimage resistance (C2SPI) for KEMs
{{XWING}}. The same notion has also been described as chosen ciphertext
resistance elsewhere {{CDM23}}.

## Binding properties

TODO

### X-BIND-K-PK security

TODO

### X-BIND-K-CT security

Ciphertext second preimage resistance for KEMs ([C2PRI]{{XWING}}). Related to
the ciphertext collision-freeness of the underlying PKE scheme of a
FO-transform KEM. Also called ciphertext collision resistance.

## Domain Separation {#domain-separation}

ASCII-encoded bytes provide oracle cloning {{BDG2020}} in the security
game via domain separation. The IND-CCA security of hybrid KEMs often
relies on the KDF function `KDF` to behave as an independent
random oracle, which the inclusion of the `label` achieves via domain
separation {{GHP2018}}.

By design, the calls to `KDF` in these constructions and usage anywhere else
in higher level protoocl use separate input domains unless intentionally
duplicating the 'label' per concrete instance with fixed paramters. This
justifies modeling them as independent functions even if instantiated by the
same KDF. This domain separation is achieved by using prefix-free sets of
`label` values. Recall that a set is prefix-free if no element is a prefix of
another within the set.

Length diffentiation is sometimes used to achieve domain separation but as a
technique it is [brittle and prone to misuse]{{BDG2020}} in practice so we
favor the use of an explicit post-fix label.

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

This document requests three new entries to the "HPKE KEM Identifiers"
registry.  These entries are defined in the following subsections.

## QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256) KEM Identifier

Value:
: 0xc1fe (please)

KEM:
: QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256)

Nsecret:
: 32

Nenc:
: 1121

Npk:
: 1217

Nsk:
: 32

Auth:
: no

Reference:
: This document

## KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256) KEM Identifier

Value:
: 0xbc48  (please)

KEM:
: KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256)

Nsecret:
: 32

Nenc:
: 1120

Npk:
: 1216

Nsk:
: 32

Auth:
: no

Reference:
: This document

## QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256) KEM Identifier

Value:
: 0x0a25 (please)

KEM:
: QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256)

Nsecret:
: 32

Nenc:
: 1617

Npk:
: 1617

Nsk:
: 32

Auth:
: no

Reference:
: This document

# Test Vectors

This section describes test vectors for each of the concrete KEMs specified
in this document.

## QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256) Test Vectors

~~~~
{::include ./spec/test-vectors-QSF-KEM(ML-KEM-768,P-256)-XOF(SHAKE256)-KDF(SHA3-256).txt}
~~~~

## KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256) Test Vectors

~~~~
{::include ./spec/test-vectors-KitchenSink-KEM(ML-KEM-768,X25519)-XOF(SHAKE256)-KDF(HKDF-SHA-256).txt}
~~~~

## QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256) Test Vectors

~~~~
{::include ./spec/test-vectors-QSF-KEM(ML-KEM-1024,P-384)-XOF(SHAKE256)-KDF(SHA3-256).txt}
~~~~

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
