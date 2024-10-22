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
  I-D.driscoll-pqt-hybrid-terminology:

--- abstract

This document defines generic techniques to achive hybrid PQ-T key
encapsulation mechanisms (KEMs) from post-quantum and traditional component
algorithms that meet specified security properties. Concrete instatiations of
techniques are located in another document.

--- middle

# Introduction {#intro}

## Motivation {#motivation}

There are many choices that can be made when specifying a hybrid KEM:
the constituent KEMs; their security levels; the combiner; and the hash
within, to name but a few. Having too many similar options are a burden
to the ecosystem.

The aim of this document is provide a small set of techniques for constructing
hybrid KEMs designed to achieve specific security properties given conforming
component algorithms,  that should be suitable for the vast majority of use cases.

## Design goals {#goals}

* Identify which KEM security properties are IETF-relevant, and provide a terse overview of those
security properties (eg. IND-CCA, LEAK-BIND-K-PK, HON-BIND-K-CT, etc), as well as security
properties unique to hybrid KEMs (component key material reuse between hybrid and non-hybrid uses or
between multiple hybrids, one component is malicious while the other is honest, etc) with reference
to literature, and put into context with real-world attacks. From that, give guidance on a sensible
baseline.

* Provide a terse overview of well-reviewed techniques that are options to safely produce the
concrete combinations in (C), and which security properties are achieved given those of the
constituents.

* Provide an initial number of explicit PQ/T hybrid KEMs using techniques from (B) that reach the
baseline set in (A), in a separate document, and should include:

       (I)  a hybrid of P-256 and ML-KEM-768,
       (II)  a hybrid of X25519 and ML-KEM-768, and,
       (III) a hybrid of P-384 and ML-KEM-1024.

These hybrids should be accompanied by pseudocode and test vectors.

This list includes two options at the ~128-bit security level (due to current
implementation/deployment trends) and one at a higher level.

### Non-iteractive

These KEMs are a non-interactive means to establish a shared secret.
Using KEMs in place of Diffie-Hellman key exchange can be done in some settings
but not all.

### Not authenticated

These KEMs are not _authenticated_.

## Design Non-Goals

There is demand for other hybrid variants that either use different
primitives (RSA, NTRU, Classic McEliece, FrodoKEM), parameters, or that
use a combiner optimized for a specific use case. Other use cases
could be covered in subsequent documents and not included here.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Conventions and Definitions

This document is consistent with all terminology defined in
{{I-D.driscoll-pqt-hybrid-terminology}}.

The following terms are used throughout this document to describe the
operations, roles, and behaviors of HPKE:

- `concat(x0, ..., xN)`: returns the concatenation of byte
  strings. `concat(0x01, 0x0203, 0x040506) = 0x010203040506`.
- `random(n)`: return a pseudorandom byte string of length `n` bytes produced by
  a cryptographically-secure random number generator.


# Hybrid KEM Security Properties

Hybrid KEM constructions ideally provide at least:

## IND-CCA security

Also known as IND-CCA1 security for general public key encryption, for KEMs
that encapsulate a new random 'message' each time,

## LEAK-BIND-K-PK security

## LEAK-BIND-K-CT security

The shared secret


# Hybrid KEM Construction Techniques

Requirements:

## KDF as a secure PRF

## IND-CCA-secure PQ KEM


## 'Kitchen Sink' construction:

Ingredients:

* KDF `F`
* label
* PQ-CT
* PQ-PK
* PQ-SS
* T-PK
* T-CT
* T-SS


~~~
def SharedSecret():
    return F(concat(PQ_SS, T_SS, PQ_CT, PQ_PK, T_CT, T_PK, label))
~~~

Label varies per combos such that the label will vary as the lengths and
other properties of the component algorithms vary. Otherwise we'd have to
hash the inputs to fixed lengths or encode lengths into the input.

## 'X-Wing' construction

Inspired by [XWING] which leverages the security properties of a KEM like
ML-KEM to elide other public data from the KDF input.

~~~
def SharedSecret():
    return F(concat(label, T_SS, PQ_SS, T_CT, T_PK))
~~~

Relies on PQ KEM having LEAK-BIND-K-CT and LEAK-BIND-K-PK security, which is
related to the collision-freeness of the underlying PKE scheme of a
FO-transform KEM like ML-KEM.

# Hybrid KEM Instatiations

See the other document.

# Security Considerations

IND-CCA, LEAK-BIND-K-PK, etc, as well as security properties unique to hybrid
KEMs (component key material reuse between hybrid and non-hybrid uses or
between multiple hybrids, one component is malicious while the other is
honest, etc)


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
