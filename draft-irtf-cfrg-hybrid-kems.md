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
  ABR01:
    title: "The Oracle Diffie-Hellman Assumptions and an Analysis of DHIES"
    date: Jan, 2001
    author:
      -
        ins: Michel Abdalla
      -
        ins: Mihir Bellare
      -
        ins: Phillip Rogaway

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

"Post-quantum" (PQ) algorithms are designed to resist attack by a quantum computer,
in contrast to "traditional" algorithms.  However, given the novelty of PQ
algorithms, there is some concern that PQ algorithms currently believed to be
secure will be broken.  Hybrid constructions that combine both PQ and
traditional algorithms can help moderate this risk while still providing
security against quantum attack. In this document, we define constructions for
hybrid Key Encapsulation Mechanisms (KEMs) based on combining a traditional KEM
and a PQ KEM. Hybrid KEMs using these constructions provide strong security
properties as long as the undelying algorithms are secure.

--- middle

# Introduction {#intro}

Post-quantum (PQ) algorithms offer new constructions based on problems tailored
towards resisting attack from a quantum computer. Key Encapsulation Mechanisms
(KEMs), are a standardized algorithm type that can be used to build protocols in
lieu of traditional, quantum-vulnerable variants such as finite field or
elliptic curve Diffie-Hellman (DH) based protocols. Upgrading key establishment
protocols to use PQ KEMs is a priority for the protocol design community, due to
the possibility of "harvest now, decrypt later" attacks.

Given the novelty of PQ algorithms, however, there is some concern that PQ
algorithms currently believed to be secure will be broken.  Hybrid
constructions that combine both PQ and traditional algorithms can help moderate
this risk while still providing security against quantum attack.  If construted
properly, a hybrid KEM will retain certain security properties even if one of
the two constituent KEMs is compromised.  If the PQ KEM is broken, then the
hybrid KEM should continue to provide security against non-quantum attackers by
virtue of its traditional KEM component.  If the traditional KEM is broken by a
quantum computer, then the hybrid KEM should continue to resist quantum attack
by virtue of its PQ KEM component.

In addition to guarding against algorithm weaknesses, this property also guards
against flaws in implementations, such as timing attacks.  Hybrid KEMs can also
facilitate faster deployment of PQ security by allowing applications to
incorporate PQ algorithms while still meeting compliance requirements based on
traditional algorithms.

In this document, we define constructions for hybrid KEMs based on combining a
traditional algorithm and a PQ KEM.  The aim of this document is provide a small
set of techniques for constructing hybrid KEMs designed to achieve specific
security properties given conforming component algorithms, which should make it
suitable for the majority of use cases.

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
- `split(N1, N2, x)`: Split a byte string `x` of length `N1 + N2` into its first
  `N1` bytes and its last `N2` bytes.  This function is the inverse of
  `concat(x1, x2)` when `x1` is `N1` bytes long and `x2` is `N2` bytes long. It
  is an error to call this function with a byte string that does not have length
  `N1 + N2`.

When `x` is a byte string, we use the notation `x[..i]` and `x[i..]` to
denote the slice of bytes in `x` starting from the beginning of `x` and
leading up to index `i`, including the `i`-th byte, and the slice the bytes
in `x` starting from index `i` to the end of `x`, respectively. For example,
if `x = [0, 1, 2, 3, 4]`, then `x[..2] = [0, 1]` and `x[2..] = [2, 3, 4]`.

# Cryptographic Dependencies {#cryptographic-deps}

The generic hybrid PQ/T KEM constructions we define depend on the the
following cryptographic primitives:

- Key Encapsulation Mechanism {{kems}}
- Hash Functions {{hash}}

In the remainder of this section, we describe functional aspects of these
mechanisms.  The security properties we require in order for the resulting
hybrid KEM to be secure are discussed in {{security-properties}}.

## Key encapsulation mechanisms {#kems}

~~~ aasvg
     +-----------------+
     | GenerateKeyPair |
     |        or       |
     |  DeriveKeyPair  |
     +--------+--------+
              |
    +---------+----------+
    |                    |
    V                    V

    ek                  dk

    |                    |
    |                    |
    V                    V
+--------+    ct    +--------+
| Encaps |--------->| Decaps |
+--------+          +--------+
    |                    |
    |                    |
    V                    V

    ss        ==        ss
~~~

A Key Encapsulation Mechanism (KEMs) comprises the following algorithms:

- `GenerateKeyPair() -> (ek, dk)`: A randomized algorithm that generates a
  public encapsulation key `ek` and a secret decapsulation key `dk`, each of
  which are byte strings.
- `DeriveKeyPair(seed) -> (ek, dk)`: A deterministic algorithm that takes as
  input a seed `seed` and generates a public encapsulation key `ek` and a secret
  decapsulation key `dk`, each of which are byte strings.
- `Encaps(ek) -> (ct, ss)`: A probabilistic encapsulation
  algorithm, which takes as input a public encapsulation key `ek` and outputs
  a ciphertext `ct` and shared secret `ss`.
- `Decaps(dk, ct) -> ss`: A decapsulation algorithm, which takes
  as input a secret decapsulation key `dk` and ciphertext `ct` and outputs a
  shared secret `ss`.

> Definitions of KEM in the literature typically do not explicitly include the
> `DeriveKeyPair` function.  It can be viewed as a "derandomized" version of
> `GenerateKeyPair`, in which the randomness used by the randomized algorithm is
> made explicit.  We call it out explicitly here because `DeriveKeyPair` is
> important to allow KEMs to integrate with protocols such as HPKE {{?RFC9180}}
> and MLS {{?RFC9420}}.

A KEM may also provide a deterministic version of `Encaps` (e.g., for purposes
of testing):

- `EncapsDerand(ek, randomness) -> (ct, shared_secret)`: A deterministic
   encapsulation algorithm, which takes as input a public encapsulation key
   `ek` and randomness `randomness`, and outputs a ciphertext `ct` and shared
   secret `shared_secret`.

<!-- XXX(RLB): Maybe we should make this optional and parallel to `EncapsDerand`
-->

We assume that the values produced and consumed by the above functions are all
byte strings, with fixed lengths:

- `Nseed`: The length in bytes of a key seed (input to DeriveKeyPair)
- `Nek`: The length in bytes of a public encapsulation key
- `Ndk`: The length in bytes of a secret decapsulation key
- `Nct`: The length in bytes of a ciphertext produced by Encaps
- `Nss`: The length in bytes of a shared secret produced by Encaps or Decaps

> This interface is effectively the same as the one defined in the Hybrid Public
> Key Encryption (HPKE) specification {{?RFC9180}}.  The only difference is that
> here we assume that all values are byte strings, whereas in HPKE keys are
> opaque by default and serialized or deserialized as needed.  We also use
> slightly different terminology for keys, emphasizing "encapsulation" and
> "decapsulation" as opposed to "public" and "secret".

## Hash functions {#hash}

Functionally, a hash function is simply a function that produces a fixed-length
output byte string from an input byte string of arbitrary length.

- `Nh` - The length in bytes of an output from this hash function.
- `Hash(input) -> output`: Produce a byte string of length `Nh` from an input
  byte string.

For simplicity, we will write invocations of a hash function without `Hash`
being explicit.  Invoking a hash function `Foo` on input `input` will be written
as `Foo(input)` instead of `Foo.Hash(input)`.

Hash function used with the constructions in this document should be structured
so that they can be regarded as random oracles in either the classical or
quantum random oracle model.  (Note that this property implies standard hash
function properties such as collision resistance and second preimage
resistance.)  Each hash function we refer to should be an independent random
oracle.

## KEM from Diffie-Hellman {#group}

This section describes a simple KEM built from a Diffie-Hellman group.  **This
KEM is not a secure KEM in the sense of the IND-CCA standard usually applied (it
meets the lower IND-CPA standard {{ABR01}}), and thus should not be used on its
own.**  However, using the constructions in this document, it can be used as a
component of an IND-CCA hybrid KEM, as discussed in {{security-considerations}}.

The traditional Diffie-Hellman construction depends on an abelian group G with a
chosen group generator or "base point" `B`, in which the discrete-log problem is
hard.  Here we write the group operation in G additively, so that "scalar
multiplication" of a non-negative integer `k` times a group element `P`
represents repeated application of the group operation to `P`:

~~~
0 * P = O (the identity element for the group)
1 * P = P
2 * P = P + P
...
k * P = (k - 1) * P + P
~~~

We call a non-negative integer in the range `[0, n)` a "scalar", where `n` is
the order of the group.

In addition to the group operation, we require that a Diffie-Hellman group
define the following algorithms:

- `RandomScalar(seed) -> k`: Produce a uniform pseudo-random scalar from the
  byte string `seed`.
- `ScalarToBytes(k) -> dk`: Encode a scalar into a fixed-length byte string.
- `BytesToScalar(dk) -> k`: Decode a scalar from a fixed-length byte string.
- `ElementToBytes(P) -> dk`: Encode an element of the group into a fixed-length
  byte string.
- `BytesToElement(dk) -> P`: Decode an element of the group from a fixed-length
  byte string.
- `ElementToSharedSecret(P) -> ss`: Extract a shared secret from an element of
  the group (e.g., by taking the X coordinate of an ellpitic curve point).

Based on this notion of a group, we can define a DH-based KEM as follows:

~~~
def GenerateKeyPair():
    seed = random(Nseed)
    return DeriveKeyPair(seed)

def DeriveKeyPair(seed):
    p = RandomScalar(seed)
    P = p * B
    dk = ScalarToBytes(p)
    ek = ElementToBytes(P)
    return (ek, dk)

def Encaps(ek):
    P = BytesToElement(ek)
    (Q, q) = GenerateKeyPair()
    ct = ElementToBytes(Q)
    ss = ElementToSharedSecret(q * P)
    return (ct, ss)

def Decaps(dk, ct)
    p = BytesToScalar(dk)
    Q = BytesToElement(ct)
    ss = ElementToSharedSecret(p * Q)
    return ss
~~~

# Hybrid KEM Constructions {#constructions}

In this section, we define a collection of constructions for hybrid KEMs. These
constructions share a common overall structure, differing mainly in how they
compute the final shared secret.

During encapsulation and decapsulation, a hybrid KEM combines its component KEM
shared secrets and other info, such as the KEM ciphertexts and encapsulation
keys secret.  This function, often called a "combiner" in the literature,
accepts the following inputs:

- `ss_PQ`: The PQ KEM shared secret.
- `ct_PQ`: The PQ KEM ciphertext.
- `ek_PQ`: The PQ KEM public encapsulation key.
- `ss_T`: The traditional KEM shared secret.
- `ct_T`: The traditional KEM ciphertext.
- `ek_T`: The traditional KEM public encapsulation key.
- `label`: A domain-separating label; see {{domain-separation}} for more
  information on the role of the label.

The output of the combiner function is a byte string that is hashed to become
the shared secret output of the KEM.

## General Construction

A hybrid KEM `KEM_H` depends on the following constituent components:

* `KEM_H.Nseed`: The length in bytes for a key seed for the hybrid KEM
* `KEM_H.Nss`: The length in bytes of a shared secret produced by the hybrid KEM
* `KEM_T`: A traditional KEM
* `KEM_PQ`: A post-quantum KEM
* `ExpandHash`: A hash function mapping byte strings of length `KEM_H.Nseed` to
  byte strings of length `KEM_T.Nseed + KEM_PQ.Nseed` (`ExpandHash.Nh ==
  KEM_T.Nseed + KEM_PQ.Nseed`)
* `CombineHash`: A hash function mapping byte strings of length `KEM_T.Nss +
  KEM_PQ.Nss` to byte strings of length `KEM_H.Nss` (`CombineHash.Nh ==
  KEM_H.Nss`)
* `Combiner(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label) -> input`: A function
  that produces a byte string from the specified inputs, from which the final
  shared secret is computed.
* `Label` - A byte string used to label the specific combination of the above
  constituents being used.

We presume the KEMs and hash functions meet the interfaces described in
{{cryptographic-deps}}.

Given these constituent parts, we define the following overall structure for a
hybrid KEM:

```
def GenerateKeyPair():
    seed = random(Nseed)
    return DeriveKeyPair(seed)

def DeriveKeyPair(seed):
    seed_full = ExpandHash(seed)
    (seed_T, seed_PQ) = split(KEM_T.Nseed, KEM_PQ.Nseed, seed)
    (ek_T, dk_T) = KEM_T.DeriveKeyPair(seed_T)
    (ek_PQ, dk_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
    ek_H = concat(ek_T, ek_PQ)
    dk_H = concat(dk_T, dk_PQ)
    return (ek_H, dk_H)

def Encaps(ek):
    (ek_T, ek_PQ) = split(KEM_T.Nek, KEM_PQ.Nek, ek)
    (ss_T, ct_T) = KEM_T.Encap(pk_T)
    (ss_PQ, ct_PQ) = KEM_PQ.Encap(pk_PQ)
    ss_H = CombinerHash(Combiner(ss_T, ct_T, ek_T, ss_PQ, ct_PQ, ek_PQ, Label))
    ct_H = concat(ct_T, ct_PQ)
    return (ss_H, ct_H)

def Decaps(dk, ct):
    (dk_T, dk_PQ) = split(KEM_T.Ndk, KEM_PQ.Ndk, dk)
    ek_T = KEM_T.ToEncaps(dk_T)
    ek_PQ = KEM_PQ.ToEncaps(dk_PQ)

    (ct_T, ct_PQ) = split(KEM_T.Nct, KEM_PQ.Nct, ct)
    ss_T = KEM_T.Decap(dk_T, ct_T)
    ss_PQ = KEM_PQ.Decap(dk_PQ, ct_PQ)

    ss_H = CombinerHash(Combiner(ss_T, ct_T, ek_T, ss_PQ, ct_PQ, ek_PQ, Label))
    return ss_H
```

The constants associated with a hybrid KEM are mostly derived from the
concatenation of keys and ciphertexts:

```
Npk = KEM_T.Npk + KEM_PQ.Npk
Nsk = KEM_T.Nsk + KEM_PQ.Nsk
Nct = KEM_T.Nct + KEM_PQ.Nct
```

The `Nseed` and `Nss` constants should reflect the overall security level of the
combined KEM, with the following recommended values:

```
Nseed = max(KEM_T.Nseed, KEM_PQ.Nseed)
Nss = min(KEM_T.Nss, KEM_PQ.Nss)
```

The remainder of this section describes four options for the `Combiner`
function.  For each combiner, we outline scenarios where it should and should
not be used.

### Everything

```
def Everything(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label):
    return concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label)
```

This combiner provides a simple construction that is broadly usable, because its
security properties are largely independent of the properties of the constituent
components.  See {{everything-sec}} for security analysis.

The major drawback of this combiner is that it can be computationally expensive.
In some PQ KEMs, the encapsulation key `ek_PQ` or ciphertext `ct_PQ` can be
large, causing `CombinerHash` to process a large input.

<!-- TODO example: Raw ECDH + something with short keys and no binding (HQC?) -->

### Pre-Hash Encapsulation Keys

```
def PreHashedKeys(ss_T, ss_PQ, ct_T, ct_PQ, ek_T, ek_PQ, label):
    ek_pre = CombinerHash(ek_T, ek_PQ)
    return concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_pre, label)
```

This combiner is an optimization over the `Everything` combiner for the case
where the same encapsulation key is being used repeatedly, and this
encapsulation key is large enough that hashing it is slow.  In such a case, the
pre-hashing can be done offline and the hash result `ek_pre` cached, so that
invocatons of the combiner can be done more quickly.  Its security follows from
that of the `Everything` combiner, since the intermediate hashing does not
affect the analysis.

If the operational assumptions above are not true -- for example, if
encapsulation keys are small or single-use -- then this combiner adds extra
hashes for no utility, and the `Everything` combiner should be preferred.

<!-- TODO example: Raw ECDH + Classic McEliece -->

### Only Traditional

```
def OnlyTraditional(ss_T, ss_PQ, ct_T, ct_PQ, ek_T, ek_PQ, label):
    return concat(ss_PQ, ss_T, ct_T, ek_T, label)
```

This combiner produces an even smaller hash input than the `PreHashedKeys`
combiner, even in cases where keys are not reused, by hashing only the
traditional metadata.

It is, however, less universal than the `Everything` or `PreHashedKeys`
combiners.  Its security depends on the constituent KEMs having certain
additional properties, as discussed in {{only-traditional-sec}}.

<!-- TODO example: Raw ECDH + ML-KEM -->

# Security Considerations

## Security Properties

### INDistinguishability against Chosen-Ciphertext Attacks (IND-CCA)

### Ciphertext Second Preimage Resistance (C2PR)

### Binding Properties (X-BIND-P-Q)

### Survival if One KEM Fails

## Security of the Combiners

### Everything {#everything-sec}

### OnlyTraditional {#only-traditional-sec}

### OnlySharedSecrets {#only-shared-secrets-sec}

# Security Considerations (Original)

Hybrid KEM constructions aim to provide security by combining two or more
schemes so that security is preserved if all but one schemes are replaced by
an arbitrarily bad scheme. Informally, these hybrid KEMs are secure if the `KDF`
is secure, and either the elliptic curve is secure, or the post-quantum KEM is
secure: this is the 'hybrid' property.

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

## Other Component Primitives

There is demand for other hybrid variants that either use different
primitives (RSA, NTRU, Classic McEliece, FrodoKEM), parameters, or that use a
combiner optimized for a specific use case. Other use cases could be covered
in subsequent documents and not included here.

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
