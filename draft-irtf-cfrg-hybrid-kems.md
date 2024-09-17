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
    ins: B.E. Westerbaan
    fullname: Bas Westerbaan
    organization: Cloudflare
    email: bas@cloudflare.com

 -
    name: Britta Hale
    org:  Naval Postgraduate School
    email: britta.hale@nps.edu

normative:

informative:


--- abstract

This memo defines the security properties and generic techniques to achive hybrid pq/t 
key encapsulation mechanisms (KEMs) from post-quantum and traditional component algorithms. 
Concrete instatiations of techniques are located in another document.

--- middle

# Introduction

We propose "Hybrid PQ/T Key Encapsulation Mechanisms", which will cover the following.

## Design Goals

(A) Identify which KEM security properties are IETF-relevant, and provide a terse overview of those
security properties (eg. IND-CCA, LEAK-BIND-K-PK, HON-BIND-K-CT, etc), as well as security
properties unique to hybrid KEMs (component key material reuse between hybrid and non-hybrid uses or
between multiple hybrids, one component is malicious while the other is honest, etc) with reference
to literature, and put into context with real-world attacks. From that, give guidance on a sensible
baseline.

(B) Provide a terse overview of well-reviewed techniques that are options to safely produce the
concrete combinations in (C), and which security properties are achieved given those of the
constituents.

(C) Provide an initial number of explicit PQ/T hybrid KEMs using techniques from (B) that reach the
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


# Hybrid KEM Security Properties

Component KEMs MUST 

# Hybrid KEM Construction Techniques

Kitchen Sink construction: 
- KDF
- label
- 

# Hybrid KEM Instatiations

See the other document.

# Security Considerations

IND-CCA, LEAK-BIND-K-PK, etc, as well as security properties unique to hybrid KEMs (component key
material reuse between hybrid and non-hybrid uses or between multiple hybrids, one component is
malicious while the other is honest, etc)


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
