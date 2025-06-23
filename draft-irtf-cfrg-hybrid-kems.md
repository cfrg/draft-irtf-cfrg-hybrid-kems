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
 -
    fullname: Richard Barnes
    organization: Cisco
    email: rlb@ipv.sx

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

  ABH+21:
    title: "Analysing the HPKE standard."
    date: April, 2021
    author:
      -
        ins: Joël Alwen
      -
        ins: Bruno Blanchet
      -
        ins: Eduard Hauck
      -
        ins: Eike Kiltz
      -
        ins: Benjamin Lipp
      -
        ins: Doreen Riepel
  ACM+25:
    title: "The Sponge is Quantum Indifferentiable"
    date: 2025
    target: https://eprint.iacr.org/2025/731.pdf
  ANSIX9.62:
    title: "Public Key Cryptography for the Financial Services Industry: the Elliptic Curve Digital Signature Algorithm (ECDSA)"
    date: Nov, 2005
    seriesinfo:
      "ANS": X9.62-2005
    author:
      -
        org: ANS
  AOB+24:
    title: "Formally verifying Kyber Episode V: Machine-checked IND-CCA security and correctness of ML-KEM in EasyCrypt"
    date: 2024
    target: https://eprint.iacr.org/2024/843.pdf
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
  BDP+08:
    title: "On the Indifferentiability of the Sponge Construction"
    target: https://www.iacr.org/archive/eurocrypt2008/49650180/49650180.pdf
    date: 2008
  BDP+11:
    title: "Cryptographic sponge functions"
    target: https://keccak.team/files/CSF-0.1.pdf
    date: 2011
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
  DRS+13:
    title: "To Hash or Not to Hash Again? (In)differentiability Results for H^2 and HMAC"
    target: https://eprint.iacr.org/2013/382.pdf
    date: 2013
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
  LBB20:
    title: "A Mechanised Cryptographic Proof of the WireGuard Virtual Private Network Protocol"
    date: 2019
    target: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8806752
  LUCKY13:
    target: https://ieeexplore.ieee.org/iel7/6547086/6547088/06547131.pdf
    title: "Lucky Thirteen: Breaking the TLS and DTLS record protocols"
    author:
    -
      ins: N. J. Al Fardan
    -
      ins: K. G. Paterson
  HKDF: RFC5869
  MRH03:
    title: "Indifferentiability, Impossibility Results on Reductions, and Applications to the Random Oracle Methodology"
    date: 2003
    target: https://eprint.iacr.org/2003/161.pdf
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
  RS92:
    title: "Non-Interactive Zero-Knowledge Proof of Knowledge and Chosen Ciphertext Attack."
    date: 1992
    target: https://link.springer.com/chapter/10.1007/3-540-46766-1_35
  Rosulek:
    title: "The Joy of Cryptography"
    date: 2021
    target: https://joyofcryptography.com/pdf/book.pdf
  RSS11:
    title: "Careful with Composition: Limitations of Indifferentiability and Universal Composability"
    date: 2011
    target: https://eprint.iacr.org/2011/339.pdf
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
  GMP22:
    title: "Anonymous, Robust Post-Quantum Public-Key Encryption"
    target: https://eprint.iacr.org/2021/708.pdf
    date: 2022
    author:
      -
        name: P. Grubbs
      -
        name: V. Maram
      -
        name: K.G. Paterson
  # XWING-EC-PROOF: https://github.com/formosa-crypto/formosa-x-wing/

--- abstract

Post-quantum (PQ) algorithms are designed to resist attack by a quantum
computer, in contrast to "traditional" algorithms.  However, given the
novelty of PQ algorithms, there is some concern that PQ algorithms currently
believed to be secure will be broken.  Hybrid constructions that combine both
PQ and traditional algorithms can help moderate this risk while still
providing security against quantum attack. In this document, we define
constructions for hybrid Key Encapsulation Mechanisms (KEMs) based on
combining a traditional KEM and a PQ KEM. Hybrid KEMs using these
constructions provide strong security properties as long as the undelying
algorithms are secure.

--- middle

# Introduction {#intro}

Post-quantum (PQ) cryptographic schemes offer new constructions based on
problems conjectured as resistant to attacks possible on a quantum
computer. Key Encapsulation Mechanisms (KEMs), are a standardized class of
cryptographic scheme that can be used to build protocols in lieu of
traditional, quantum-vulnerable variants such as finite field or elliptic
curve Diffie-Hellman (DH) based protocols.

Given the novelty of PQ algorithms, however, there is some concern that PQ
algorithms currently believed to be secure will be broken.  Hybrid
constructions that combine both PQ and traditional algorithms can help
moderate this risk while still providing security against quantum attack.  If
construted properly, a hybrid KEM will retain certain security properties
even if one of the two constituent KEMs is compromised. If the PQ KEM is
broken, then the hybrid KEM should continue to provide security against
non-quantum attackers by virtue of its traditional KEM component. If the
traditional KEM is broken by a quantum computer, then the hybrid KEM should
continue to resist quantum attack by virtue of its PQ KEM component.

In addition to guarding against algorithm weaknesses, this property also
guards against flaws in implementations, such as timing attacks.  Hybrid KEMs
can also facilitate faster deployment of PQ security by allowing applications
to incorporate PQ algorithms while still meeting compliance requirements
based on traditional algorithms.

In this document, we define generic schemes for constructing hybrid KEMs from
a traditional algorithm and a PQ KEM.  The aim of this document is provide a
small set of techniques to achieve specific security properties given
conforming component algorithms, which should make these techniques suitable
for a broad variety of use cases.

The remainder of this document is structured as follows: first, in
{{cryptographic-deps}} and {{schemes}}, we define the abstractions on which
the schemes are built, and then the schemes themselves.  Then, in
{{security}}, we lay out the security analyses that support these
constructions, including the security requirements for constituent components
and the security notions satisfied by hybrid KEMS constructed according to
the schemes in the document {{security-requirements}}.  Finally, we discuss
some "path not taken", related topics that might be of interest to readers,
but which are not treated in depth.

# Requirements Notation

{::boilerplate bcp14-tagged}

# Notation

This document is consistent with all terminology defined in
{{?I-D.ietf-pquip-pqt-hybrid-terminology}}.

The following terms are used throughout this document:

- `random(n)`: return a pseudorandom byte string of length `n` bytes produced
  by a cryptographically-secure random number generator.
- `concat(x0, ..., xN)`: Concatenation of byte strings.  `concat(0x01,
  0x0203, 0x040506) = 0x010203040506`.
- `split(N1, N2, x)`: Split a byte string `x` of length `N1 + N2` into its
  first `N1` bytes and its last `N2` bytes.  This function is the inverse of
  `concat(x1, x2)` when `x1` is `N1` bytes long and `x2` is `N2` bytes
  long. It is an error to call this function with a byte string that does not
  have length `N1 + N2`. Since this function operates over secret data `x`,
  it MUST be constant-time for a given `N1` and `N2`.

When `x` is a byte string, we use the notation `x[..i]` and `x[i..]` to
denote the slice of bytes in `x` starting from the beginning of `x` and
leading up to index `i`, including the `i`-th byte, and the slice the bytes
in `x` starting from index `i` to the end of `x`, respectively. For example,
if `x = [0, 1, 2, 3, 4]`, then `x[..2] = [0, 1]` and `x[2..] = [2, 3, 4]`.

# Cryptographic Dependencies {#cryptographic-deps}

The generic hybrid PQ/T KEM constructions we define depend on the the
following cryptographic primitives:

- Key Encapsulation Mechanisms ({{kems}})
- Nominal Groups ({{groups}})
- Key Derivation Functions ({{kdfs}})
- Pseudorandom Generators ({{prgs}})

<!-- [RLB] Why do we need PRGs and KDFs?  It seems like the proofs that we're
trying to match don't make different assumptions about them (they're all ROs),
and the API is clearly the same.  But if we can't come to agreement, I'm fine
throwing this to the WG. -->

<!-- [RLB] Nit: I would reverse the order of the PRG and KDF sections, to match
the order in which they are used. -->

In the remainder of this section, we describe functional aspects of these
mechanisms.  The security properties we require in order for the resulting
hybrid KEM to be secure are discussed in {{security}}.

## Key encapsulation mechanisms {#kems}

~~~ aasvg
     +-----------------+
     | GenerateKeyPair |
     |       or        |
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
  input a seed `seed` and generates a public encapsulation key `ek` and a
  secret decapsulation key `dk`, each of which are byte strings.
- `Encaps(ek) -> (ct, ss)`: A probabilistic encapsulation
  algorithm, which takes as input a public encapsulation key `ek` and outputs
  a ciphertext `ct` and shared secret `ss`.
- `Decaps(dk, ct) -> ss`: A decapsulation algorithm, which takes
  as input a secret decapsulation key `dk` and ciphertext `ct` and outputs a
  shared secret `ss`.

A KEM may also provide a deterministic version of `Encaps` (e.g., for
purposes of testing):

- `EncapsDerand(ek, randomness) -> (ct, shared_secret)`: A deterministic
   encapsulation algorithm, which takes as input a public encapsulation key
   `ek` and randomness `randomness`, and outputs a ciphertext `ct` and shared
   secret `shared_secret`.

We assume that the values produced and consumed by the above functions are
all byte strings, with fixed lengths:

- `Nseed`: The length in bytes of a key seed (input to DeriveKeyPair)
- `Nek`: The length in bytes of a public encapsulation key
- `Ndk`: The length in bytes of a secret decapsulation key
- `Nct`: The length in bytes of a ciphertext produced by Encaps
- `Nss`: The length in bytes of a shared secret produced by Encaps or Decaps

## Nominal Groups {#groups}

~~~ aasvg
                            g
                            |
             +--------------+---------------+
             |                              |
             V                              V
          +-----+                        +-----+
       +->| Exp |                        | Exp |<-+
       |  +-----+                        +-----+  |
       |     |                              |     |
       |     |                              |     |
       |     V                              V     |
       |    pkA                            pkB    |
       |     |                              |     |
 skA --+     +-------------.  .-------------+     +-- skB
       |                    \/                    |
       |                    /\                    |
       |     +-------------'  '-------------+     |
       |     |                              |     |
       |     V                              V     |
       |  +-----+                        +-----+  |
       +->| Exp |                        | Exp |<-+
          +-----+                        +-----+
             |                              |
             |                              |
             V                              V
           pkAB ========================= pkBA
~~~

<!-- [DC] Yes we need to be able to model the group as a nominal group to make the
proofs work, but we have proofs for the NIST curves and the Montgomery curves,
I wouldn't be surprised if a nice prime order group like Ristretto or DoubleOdd
could also be shown to be a nominal group; thoughts on putting the 'nominal'
requirements in the security bits at the bottom of the doc, and just leave this as
'Groups'? -->

<!-- [RLB] I'm fine keeping the "Nominal" for now, since it's what they're
called in ABH+21.  It doesn't hurt to restate the criteria below, just like we
do (should) with KDFs / PRGs / whatever. -->

Nominal groups are an abstract model of elliptic curve groups, over which we
instantiate Diffie-Hellman key agreement {{ABH+21}}.  A nominal group
comprises a set `G` together with a distinguished basis element `g`, an
"exponentiation" map, and some auxiliary functions:

- `Exp(p, x) -> q`: An algorithm that produces an element `q` of `G` from an
  element `p` and an integer `x`.
    * The integers `x` are called "scalars" to distinguish them from group
      elements.
    * `Exp` must respect multiplication in its scalar argument `x`, so that
      `Exp(Exp(p, x), y) = Exp(p, x * y)`.
- `RandomScalar(seed) -> k`: Produce a uniform pseudo-random scalar from the
  byte string `seed`.
- `ElementToSharedSecret(P) -> ss`: Extract a shared secret from an element of
  the group (e.g., by taking the X coordinate of an ellpitic curve point).

We assume that scalars and group elements are represented by byte strings with
fixed lengths:

- `Nseed`: The length in bytes of a seed (input to RandomScalar)
- `Nscalar`: The length in bytes of a scalar
- `Nelem`: The length in bytes of a serialized group element
- `Nss`: The length in bytes of a shared secret produced by
  ElementToSharedSecret

The security requirements for groups used with the schemes in this document
are laid out in {{security-groups}}.

## Key Derivation Functions {#kdfs}

A Key Derivation Function (KDF) is a function that a function that produces
keying material based on an input secret and other information.

While KDFs in the literature can typically consume and produce byte strings of
arbitrary length, the KDFs used in this document have a simpler form, with a fixed
output lengths:

- `Nin` - The length in bytes of an input to this KDF.
- `Nout` - The length in bytes of an output from this KDF.
- `KDF(input) -> output`: Produce a byte string of length `Nout` from an input
  byte string.

<!-- [RLB] We don't actually need to refer to `Nin` below, so we could safely
drop it.  Or if we keep it, we should treat it as a maximum and specify that it
is at least a certain size, `Nin >= Nseed` for PRG.  I would probably just drop
it, though. -->

The fixed sizes are for both security and simplicity.

For instances of the `Extract()`/`Expand()` KDF paradigm such as `HKDF`, we fix
the salt and sizes to fit this form.

The security requirements for KDFs used with the schemes in this document are
laid out in {{security-kdfs}}.

## `PRG` {#prgs}

A pseudorandom generator (PRG) is a deterministic function `G` whose outputs
are longer than its inputs. When the input to `G` is chosen uniformly at
random, it induces a certain distribution over the possible output. The
output distribution is pseudorandom if it is indistinguishable from the
uniform distribution.

The PRGs used in this document have a simpler form, with a fixed
output lengths:

- `Nin` - The length in bytes of an input to this PRG.
- `Nout` - The length in bytes of an output from this PRG which is longer
  than `Nin`.
- `PRG(seed) -> output`: Produce a byte string of length `Nout` from an input
  byte string `seed`.

The fixed sizes are for both security and simplicity.

MUST provide the bit-security required to source input randomness for PQ/T
components from a seed that is expanded to a output length, of which a subset
is passed to the component key generation algorithms.

The security requirements for PRGs used with the schemes in this document are
laid out in {{security-prgs}}.

# Hybrid KEM Schemes {#schemes}

In this section, we define three generic schemes for building for hybrid
KEMs:

* `GHP` - A generic construction that is suitable for use with any choice of
  traditional and PQ KEMs, with minimal security assumptions on the
  constituent KEMs
* `PRE` - A performance optimization of `GHP` for the case where
  encapsulation keys are large and frequently reused
* `QSF` - An optimized generic construction for the case where the
  traditional component is a nominal group and the PQ component has strong
  binding properties

<!-- [RLB] Nit: I wouldn't surround these names in backticks -->

<!-- [RLB] Some notes on names:
* Willing to consider QSF on the grounds that it's from the paper.
* I don't love "PRE", just because it's not an acronym.  If we're going with
  QSF, maybe we just call it "Chempat"?
* Is there some name in the GHP paper for the construction we're using here?

In other words, "We use names from the papers that describe these things" seems
like a plausible theory, let's just work it through.
-->

These schemes share a common overall structure, differing mainly in how they
compute the final shared secret and the security requirements of their
components.

## `GHP` {#ghp}

The `GHP` hybrid KEM depends on the following constituent
components:

* `KEM_T`: A traditional KEM
* `KEM_PQ`: A post-quantum KEM
* `PRG`: A PRG producing byte strings of length `KEM_T.Nseed + KEM_PQ.Nseed`
  (`PRG.Nout == KEM_T.Nseed + KEM_PQ.Nseed`)
* `KDF`: A KDF producing byte strings of length `GHP.Nss` (`KDF.Nout
  == GHP.Nss`)
* `Label` - A byte string used to label the specific combination of the above
  constituents being used.

The KEMs, groups, KDFs, and PRGs MUST meet the security requirements in
{{security-requirements}}.

The constants associated with the hybrid KEM are mostly derived from the
concatenation of keys and ciphertexts:

~~~
Nek = KEM_T.Nek + KEM_PQ.Nek
Ndk = KEM_T.Ndk + KEM_PQ.Ndk
Nct = KEM_T.Nct + KEM_PQ.Nct
~~~

The `Nseed` and `Nss` constants should reflect the overall security level of the
combined KEM, with the following recommended values:

~~~
Nseed = max(KEM_T.Nseed, KEM_PQ.Nseed)
Nss = min(KEM_T.Nss, KEM_PQ.Nss)
~~~

Given these constituent parts, the `GHP` hybrid KEM is defined as
follows:

~~~
def GenerateKeyPair():
    seed = random(Nseed)
    return DeriveKeyPair(seed)

def DeriveKeyPair(seed):
    seed_full = PRG(seed)
    (seed_T, seed_PQ) = split(KEM_T.Nseed, KEM_PQ.Nseed, seed_full)
    (ek_T, dk_T) = KEM_T.DeriveKeyPair(seed_T)
    (ek_PQ, dk_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)
    ek_H = concat(ek_T, ek_PQ)
    dk_H = concat(dk_T, dk_PQ)
    return (ek_H, dk_H)

def Encaps(ek):
    (ek_T, ek_PQ) = split(KEM_T.Nek, KEM_PQ.Nek, ek)
    (ss_T, ct_T) = KEM_T.Encap(pk_T)
    (ss_PQ, ct_PQ) = KEM_PQ.Encap(pk_PQ)
    ss_H = KDF(concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label))
    ct_H = concat(ct_T, ct_PQ)
    return (ss_H, ct_H)

def Decaps(dk, ct):
    (dk_T, dk_PQ) = split(KEM_T.Ndk, KEM_PQ.Ndk, dk)
    ek_T = KEM_T.ToEncaps(dk_T)
    ek_PQ = KEM_PQ.ToEncaps(dk_PQ)

    (ct_T, ct_PQ) = split(KEM_T.Nct, KEM_PQ.Nct, ct)
    ss_T = KEM_T.Decap(dk_T, ct_T)
    ss_PQ = KEM_PQ.Decap(dk_PQ, ct_PQ)

    ss_H = KDF(concat(ss_PQ, ss_T, ct_PQ, ct_T, ek_PQ, ek_T, label))
    return ss_H
~~~

## `PRE`  {#pre}

The `PRE` hybrid KEM is a performance optimization of the `GHP` KEM,
optimized for the case where encapsulation keys are large and frequently
reused. In such cases, hashing the entire encapsulation key is expensive, and
the same value is hashed repeatedly.  The `PRE` KEM thus computes an
intermediate hash of the hybrid encapsulation key, so that the hash value can
be computed once and used across many encapsulation or decapsulation
operations.

The `PRE` KEM is identical to the `GHP` KEM except for the
shared secret computation.  One additional KDF is required:

<!-- [DC] We don't actually know the requirements of _this_ function, we don't
have a proof or requirements laid out; the only example from Chempat is
SHA3-256. -->

<!-- [RLB] That seems like a fine thing to flag for the RG. -->

* `KeyHash`: A KDF producing byte strings of length `GHP.Nss` (`KeyHash.Nout
  == GHP.Nss`)

The `GenerateKeyPair` and `DeriveKeyPair` algorithms for `PRE` are
identical to those of the `GHP` KEM.  The `Encaps` and `Decaps`
method use a modified shared secret computation:

~~~
def Encaps(ek):
    (ek_T, ek_PQ) = split(KEM_T.Nek, KEM_PQ.Nek, ek)
    (ss_T, ct_T) = KEM_T.Encap(pk_T)
    (ss_PQ, ct_PQ) = KEM_PQ.Encap(pk_PQ)

    ekh = KeyHash(concat(ek_T, ek_PQ))
    ss_H = KDF(concat(ss_PQ, ss_T, ct_PQ, ct_T, ekh, label))

    ct_H = concat(ct_T, ct_PQ)
    return (ss_H, ct_H)

def Decaps(dk, ct):
    (dk_T, dk_PQ) = split(KEM_T.Ndk, KEM_PQ.Ndk, dk)
    ek_T = KEM_T.ToEncaps(dk_T)
    ek_PQ = KEM_PQ.ToEncaps(dk_PQ)

    (ct_T, ct_PQ) = split(KEM_T.Nct, KEM_PQ.Nct, ct)
    ss_T = KEM_T.Decap(dk_T, ct_T)
    ss_PQ = KEM_PQ.Decap(dk_PQ, ct_PQ)

    ekh = KeyHash(concat(ek_T, ek_PQ))
    ss_H = KDF(concat(ss_PQ, ss_T, ct_PQ, ct_T, ekh, label))
    return ss_H
~~~

## `QSF` {#qsf}

The `QSF` hybrid KEM (`QSF` below) depends on the following constituent
components:

* `Group_T`: A nominal group
* `KEM_PQ`: A post-quantum KEM
* `PRG`: A PRG producing byte strings of length `Group_T.Nseed +
  KEM_PQ.Nseed` (`Expand.Nout == Group_T.Nseed + KEM_PQ.Nseed`)
* `KDF`: A KDF producing byte strings of length `QSF.Nss` (`KDF.Nout
  == KDF.Nss`)
* `Label` - A byte string used to label the specific combination of the above
  constituents being used.

We presume that `Group_T`, `KEM_PQ`, and the KDFs meet the interfaces
described in {{cryptographic-deps}} and MUST meet the security requirements
described in {{security-requirements}}.

The constants associated with the hybrid KEM are mostly derived from the
concatenation of keys and ciphertexts:

~~~
Nek = Group_T.Nelem + KEM_PQ.Nek
Ndk = Group_T.Nscalar + KEM_PQ.Ndk
Nct = Group_T.Nelem + KEM_PQ.Nct
~~~

The `Nseed` and `Nss` constants should reflect the overall security level of
the combined KEM, with the following recommended values:

~~~
Nseed = max(Group_T.Nseed, KEM_PQ.Nseed)
Nss = min(Group_T.Nss, KEM_PQ.Nss)
~~~

Given these constituent parts, we define the `QSF` hybrid KEM as follows:

~~~
def GenerateKeyPair():
    seed = random(Nseed)
    return DeriveKeyPair(seed)

def DeriveKeyPair(seed):
    seed_full = PRG(seed)
    (seed_T, seed_PQ) = split(Group_T.Nseed, KEM_PQ.Nseed, seed)

    dk_T = Group_T.RandomScalar(seed_T))
    ek_T = Group_T.Exp(Group_T.g, dk_T)
    (ek_PQ, dk_PQ) = KEM_PQ.DeriveKeyPair(seed_PQ)

    ek_H = concat(ek_T, ek_PQ)
    dk_H = concat(dk_T, dk_PQ)
    return (ek_H, dk_H)

def Encaps(ek):
    (ek_T, ek_PQ) = split(Group_T.Nek, KEM_PQ.Nek, ek)

    sk_E = Group_T.RandomScalar(random(GroupT.Nseed))
    ct_T = Group_T.Exp(GroupT.g, sk_E)
    ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ek_T, sk_E))
    (ss_PQ, ct_PQ) = KEM_PQ.Encap(ek_PQ)

    ss_H = KDF(concat(ss_PQ, ss_T, ct_T, ek_T, Label))
    ct_H = concat(ct_T, ct_PQ)
    return (ss_H, ct_H)

def Decaps(dk, ct):
    (dk_T, dk_PQ) = split(Group_T.Ndk, KEM_PQ.Ndk, dk)
    (ct_T, ct_PQ) = split(Group_T.Nct, KEM_PQ.Nct, ct)

    ek_T = Group_T.ToEncaps(dk_T)
    ek_PQ = KEM_PQ.ToEncaps(dk_PQ)

    ss_T = Group_T.ElementToSharedSecret(Group_T.Exp(ct_T, dk_T))
    ss_PQ = KEM_PQ.Decap(dk_PQ, ct_PQ)

    ss_H = KDF(concat(ss_PQ, ss_T, ct_T, ek_T, Label))
    return ss_H
~~~

# Security Considerations {#security}

Hybrid KEM constructions aim to provide security by combining two or more
schemes so that security is preserved if all but one schemes are replaced by
an arbitrarily bad scheme. Informally, these hybrid KEMs are secure if the
`KDF` is secure, and either the traditional component is secure, or the post-quantum
KEM is secure: this is the 'hybrid' property.

## Security Properties {#security-properties}

### IND-CCA Security {#ind-cca}

Also known as IND-CCA2 security for general public key encryption, for KEMs
that encapsulate a new random 'message' each time.

The notion of INDistinguishability against Chosen-Ciphertext Attacks
(IND-CCA) {{RS92}} is now widely accepted as the standard security notion for
asymmetric encryption schemes. IND-CCA security requires that no efficient
adversary can recognize which of two messages is encrypted in a given
ciphertext, even if the two candidate messages are chosen by the adversary
himself.

### Ciphertext Second Preimage Resistant (C2PRI) Security {#c2pri}

Also known in the literature as ciphertext collision resistance (CCR).

The notion where, even if a KEM has broken IND-CCA security (either due to
construction, implementation, or other), its internal structure, based on the
Fujisaki-Okamoto transform, guarantees that it is impossible to find a second
ciphertext that decapsulates to the same shared secret `K`: this notion is
known as ciphertext second preimage resistance (C2SPI) for KEMs
{{XWING}}. The same notion has also been described as chosen ciphertext
resistance elsewhere {{CDM23}}.

## Binding Properties {#binding-properties}

It is often useful for a KEM to have certain "binding properties", by which
certain parameters determine certain others {{CDM23}}.  These properties are
referred to with labels of the form X-BIND-P-Q.  For example, LEAK-BIND-K-PK
means that for a given shared secret (K), there is a unique encapsulation key
(PK) that could have produced it, even if all of the secrets involved are
given to the adversary after the encapsulation operation is completed (LEAK).

The property LEAK-BIND-K,PK-CT is related to the C2PRI property discussed
above.  Related to the ciphertext collision-freeness of the underlying PKE
scheme of a FO-transform KEM. Also called ciphertext collision resistance.

<!-- TODO: Discuss other salient binding properties. -->

## Security Requirements for Constituent Components {#security-requirements}

> TODO: We need to provide more thorough description, and verify that these
> requirements align with the requirements of the security proofs in the
> literature, especially {{GHP2018}} and {{XWING}}.

### Security Requirements for KEMs {#security-kems}

Component KEMs MUST be IND-CCA-secure {{GHP2018}} {{XWING}}.

For instances of `QSF`, the component KEM MUST also be ciphertext second
preimage resistant (C2PRI) {{XWING}}: this allows the component KEM
encapsulation key and ciphertext to be left out from the KDF input.

### Security Requirements for Groups {#security-groups}

The groups MUST be modelable as nominal groups in which the strong
Diffie-Hellman problem holds {{ABH+21}} {{XWING}}.

The Montgomery curves Curve25519 and Curve448 have been shown to be modelable
as nominal groups in {{ABH+21}} as well as showing the `X25519()` and
`X448()` functions respectively pertain to the nominal group `exp(X, y)`
function, specifically clamping secret keys when they are generated, instead
of clamping secret keys together with exponentiation.

<!-- The short Weierstrass NIST curves have also been shown to be modelable
as nominal groups but I can't find the reference -->

### Security Requirements for KDFs {#security-kdfs}

KDFs MUST be secure pseudorandom functions (PRFs) when keyed with the shared
secret output from the post-quantum IND-CCA-secure KEM component algorithm in
`QSF` {{XWING}} or any of the component IND-CCA-secure KEMs when used in
KitchenSink {{GHP2018}} or PreHash.

KDFs must be secure instances of random oracles in the ROM and QROM
{{GHP2018}} {{XWING}}. Proofs of indifferentiability from random oracles
{{MRH03}} give good confidence here, as any function proven indifferentiable
from a random oracle is resistant against collision, first, and second
preimage attacks <!-- need a good cite here -->. An indifferentiability bound
guarantees security against specific attacks. Although indifferentiability
does not capture all properties of a random oracle {{RSS11}},
indifferentiability still remains the best way to rule out structural
attacks.

Sponge-based constructions such as SHA-3 have been shown to be
indifferentiable against classical {{BDP+08}} as well as quantum adversaries
{{ACM+25}}.

HKDF has been shown to be indifferentiable from a random oracle under
specific constraints {{LBB20}}:

- that HMAC is indifferentiable from a random oracle,
which for HMAC-SHA-256 has been shown in {{DRS+13}}, assuming the
compression function underlying SHA-256 is a random oracle,
which it is indifferentiably when used prefix-free.

- the values of `HKDF`'s `IKM` input do not collide with
values of `info` `||` `0x01`. This MUST be enforced by the
concrete instantiations that use `HKDF` as its KDF.

The choice of the KDF security level SHOULD be made based on the
security level provided by the constituent KEMs. The KDF SHOULD
at least have the security level of the strongest constituent KEM.

### Security Requirements for PRGs {#security-prgs}

The functions used to expand a key seed to multiple key seeds is closer to a
pseudorandom generator (PRG) in its security requirements {{AOB+24}}. A
secure PRG is an algorithm PRG : {0, 1}^n → {0, 1}^m, such that no
polynomial-time adversary can distinguish between PRG(r) (for r $← {0, 1}^n)
and a random z $← {0, 1}^m {{Rosulek}}. The uniform string r ∈ {0, 1}^n is
called the seed of the PRG.

A PRG is not to be confused with a random (or pseudorandom) _number_
generator (RNG): a PRG requires the seed randomness to be chosen uniformly
and extend it; an RNG takes sources of noisy data and transforms them into
uniform outputs.

A PRG is a particular mode of use of a random oracle {{BDP+11}}.  Examples
used in such a manner include SHAKE256.

## Security Properties of Hybrid KEMs

<!-- TODO: Define which properties are provided by the hybrid KEMs in this -->
<!-- document, and citations to the papers with the corresponding proofs. -->

All generic constructions in this document produce IND-CCA-secure KEMs
when correctly instantiated concretely with cryptographic components that
meet the respective security requirements. Any changes to the routines,
including key generation/derivation, are not guaranteed to produce
secure results.

## Other Considerations

### Domain Separation {#domain-separation}

ASCII-encoded bytes provide oracle cloning {{BDG2020}} in the security game
via domain separation. The IND-CCA security of hybrid KEMs often relies on
the KDF function `KDF` to behave as an independent random oracle, which the
inclusion of the `label` achieves via domain separation {{GHP2018}}.

By design, the calls to `KDF` in these constructions and usage anywhere else
in higher level protoocl use separate input domains unless intentionally
duplicating the 'label' per concrete instance with fixed paramters. This
justifies modeling them as independent functions even if instantiated by the
same KDF. This domain separation is achieved by using prefix-free sets of
`label` values. Recall that a set is prefix-free if no element is a prefix of
another within the set.

Length diffentiation is sometimes used to achieve domain separation but as a
technique it is brittle and prone to misuse {{BDG2020}} in practice so we
favor the use of an explicit post-fix label.

### Fixed-length

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
fixed-length shared secrets.

# Out of Scope

Considerations that were considered and not included in these designs:

Anonymity {{GMP22}}, Deniability, Obfuscation, other forms of key-robustness
or binding {{GMP22}}, {{CDM23}}

TODO: deniable KEM cite and Kemeleon paper cite

## More than two component KEMs

Design team decided to restrict the space to only two components, a
traditional and a post-quantum KEM.

## Parameterized output length

Not analyzed as part of any security proofs in the literature, and a
complicatation deemed unnecessary.

<!-- [RLB] It might help with domain separation if we made a registry of labels,
basicaly just (label, reference), specification required.  Maybe (label, scheme,
T, PQ, PRG, KDF, reference) if you want to put a summary there.  Though in the
latter case I would not require uniqueness of the non-label values. -->

--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
