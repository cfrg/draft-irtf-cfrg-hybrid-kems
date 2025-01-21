# WARNING This is a specification of QSF-SHA3-256-ML-KEM-768-P-256;
# not a production-ready implementation. It is slow and does not run
# in constant time.

import os
import hashlib
from util import *
from kem import *

import mlkem
from sagelib.groups import GroupP256

label = "QSF-SHA3-256-ML-KEM-768-P-256"
as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

def expandDecapsulationKey(seed):
    # XXX(caw): spec update for expanded_len
    expanded_len = 112 # 64 + 48 
    expanded = hashlib.shake_256(seed).digest(length=expanded_len)
    pkM, skM = mlkem.KeyGen(expanded[0:64], mlkem.params768)
    g = GroupP256()
    skX = OS2IP(expanded[64:]) % g.order()
    pkX = skX * g.generator()
    pkXenc = g.serialize(pkX)
    return skM, skX, pkM, pkXenc

def Combiner(ssM, ssX, ctX, pkX):
    return hashlib.sha3_256(
        ssM +
        ssX +
        ctX +
        pkX +
        as_bytes(label)
    ).digest()

def DeriveKeyPair(seed):
    assert len(seed) == 32
    skM, skX, pkM, pkX = expandDecapsulationKey(seed)
    return seed, pkM + pkX

def GenerateKeyPair():
    sk = os.urandom(32)
    _, _, pkM, pkX = expandDecapsulationKey(sk)
    return sk, pkM + pkX

def EncapsulateDerand(pk, eseed):
    assert len(eseed) == 80 # XXX(caw): spec update for eseed len
    assert len(pk) == 1217
    pkM = pk[0:1184]
    pkXenc = pk[1184:1217]
    
    g = GroupP256()
    pkX = g.deserialize(pkXenc)
    ekX = OS2IP(eseed[32:]) % g.order()
    ssXbase = ekX * pkX
    xCoord = ssXbase[0] # X-coordinate
    ssX = I2OSP(xCoord, 32)

    ctX = g.serialize(ekX * g.generator())

    ctM, ssM = mlkem.Enc(pkM, eseed[0:32], mlkem.params768)

    ss = Combiner(ssM, ssX, ctX, pkXenc)
    return ss, ctM + ctX

def Decapsulate(ct, sk):
    assert len(ct) == 1121
    assert len(sk) == 32

    skM, skX, pkM, pkX = expandDecapsulationKey(sk)
    
    g = GroupP256()
    ctM = ct[0:1088]
    ctXbytes = ct[1088:1121]

    ctX = g.deserialize(ctXbytes)
    
    ssM = mlkem.Dec(skM, ctM, mlkem.params768)
    
    ssXbase = skX * ctX
    xCoord = ssXbase[0] # X-coordinate
    ssX = I2OSP(xCoord, 32)

    return Combiner(ssM, ssX, ctXbytes, pkX)

class QSFMLKEM768P256(KEM):
    def __init__(self):
        KEM.__init__(self, label)

    def Nseed(self):
        return 32
    
    def Neseed(self):
        return 80
    
    def Npk(self):
        return 1217
    
    def Nsk(self):
        return 32
    
    def Nct(self):
        return 1121
    
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