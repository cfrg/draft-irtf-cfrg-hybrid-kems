# WARNING This is a specification of KitchenSink-HKDF-SHA-256-ML-KEM-768-X25519;
# not a production-ready implementation. It is slow and does not run
# in constant time.

import os
import hmac
import hashlib
from util import *
from kem import *
import x25519
import mlkem

label = "KitchenSink-HKDF-SHA-256-ML-KEM-768-X25519"
as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

def hkdf_extract(salt, ikm):
    hash_len = hashlib.sha256().digest_size
    if salt == None or len(salt) == 0:
        salt = bytearray((0,) * hash_len)
    return hmac.new(bytes(salt), ikm, hashlib.sha256).digest()

def hkdf_expand(prk, info, length):
    hash_len = hashlib.sha256().digest_size
    length = int(length)
    assert length < 255 * hash_len
    blocks_needed = length // hash_len + (0 if length % hash_len == 0 else 1) # ceil
    okm = b""
    output_block = b""
    for counter in range(blocks_needed):
        output_block = hmac.new(prk, output_block + info + bytearray((counter + 1,)), hashlib.sha256).digest()
        okm += output_block
    return okm[:length]

def LabeledExtract(salt, label, ikm):
    labeled_ikm = as_bytes(label) + ikm
    return hkdf_extract(salt, labeled_ikm)

def LabeledExpand(prk, label, info, L):
    labeled_info = I2OSP(L, 2) + as_bytes(label) + as_bytes(info)
    return hkdf_expand(prk, labeled_info, L)

def LabeledHKDF(preimage):
    prk = LabeledExtract("", "hybrid_prk", preimage)
    return LabeledExpand(prk, "shared_secret", "", 32)

def expandDecapsulationKey(seed):
    expanded_len = 96
    expanded = hashlib.shake_256(seed).digest(length=expanded_len)
    pkM, skM = mlkem.KeyGen(expanded[0:64], mlkem.params768)
    skX = expanded[64:96]
    pkX = x25519.X(skX, x25519.BASE)
    return skM, skX, pkM, pkX

def DeriveKeyPair(seed):
    assert len(seed) == 32
    skM, skX, pkM, pkX = expandDecapsulationKey(seed)
    return seed, pkM + pkX

def GenerateKeyPair():
    sk = os.urandom(32)
    _, _, pkM, pkX = expandDecapsulationKey(sk)
    return sk, pkM + pkX

def EncapsulateDerand(pk, eseed):
    assert len(eseed) == 64
    assert len(pk) == 1216
    pkM = pk[0:1184]
    pkX = pk[1184:1216]
    
    ekX = eseed[32:64]
    ctX = x25519.X(ekX, x25519.BASE)
    ssX = x25519.X(ekX, pkX)

    ctM, ssM = mlkem.Enc(pkM, eseed[0:32], mlkem.params768)

    ss = LabeledHKDF(ssM + ssX + ctM + pkM + ctX + pkX + as_bytes(label))
    return ss, ctM + ctX

def Decapsulate(ct, sk):
    assert len(ct) == 1120
    assert len(sk) == 32

    skM, skX, pkM, pkX = expandDecapsulationKey(sk)
    
    ctM = ct[0:1088]
    ctX = ct[1088:1120]
    ssM = mlkem.Dec(skM, ctM, mlkem.params768)
    ssX = x25519.X(skX, ctX)

    return LabeledHKDF(ssM + ssX + ctM + pkM + ctX + pkX + as_bytes(label))

class KitchenSinkMLKEM768X25519(KEM):
    def __init__(self):
        KEM.__init__(self, label)

    def Nseed(self):
        return 32
    
    def Neseed(self):
        return 64
    
    def Npk(self):
        return 1216
    
    def Nsk(self):
        return 32
    
    def Nct(self):
        return 1120
    
    def GenerateKeyPair(self):
        return GenerateKeyPair()

    def DeriveKeyPair(self, seed):
        return DeriveKeyPair(seed)
    
    def Encaps(self, pk):
        eseed = os.urandom(80)
        return EncapsulateDerand(pk, eseed)
    
    def EncapsDerand(self, pk, eseed):
        return EncapsulateDerand(pk, eseed)
    
    def Decaps(self, sk, ct):
        return Decapsulate(ct, sk)

if __name__ == "__main__":
    sk, pk = GenerateKeyPair()