# WARNING This is a specification of QSF-SHA3-256-ML-KEM-1024-P-384;
# not a production-ready implementation. It is slow and does not run
# in constant time.

import os
import hashlib
from util import *
from kem import *

import mlkem
from sagelib.groups import GroupP384

label = "QSF-SHA3-256-ML-KEM-1024-P-384"
as_bytes = lambda x: x if isinstance(x, bytes) else bytes(x, "utf-8")

def expandDecapsulationKey(seed):
    expanded_len = 136
    expanded = hashlib.shake_256(seed).digest(length=expanded_len)
    pkM, skM = mlkem.KeyGen(expanded[0:64], mlkem.params1024)
    g = GroupP384()
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

def EncapsulateDerand(pk, randomness):
    assert len(randomness) == 104
    assert len(pk) == 1617
    pkM = pk[0:1568]
    pkXenc = pk[1568:1617]
    
    g = GroupP384()
    pkX = g.deserialize(pkXenc)
    ekX = OS2IP(randomness[32:]) % g.order()
    ssXbase = ekX * pkX
    xCoord = ssXbase[0] # X-coordinate
    ssX = I2OSP(xCoord, 48)

    ctX = g.serialize(ekX * g.generator())

    ctM, ssM = mlkem.Enc(pkM, randomness[0:32], mlkem.params1024)

    ss = Combiner(ssM, ssX, ctX, pkXenc)
    return ss, ctM + ctX

def Decapsulate(ct, sk):
    assert len(ct) == 1617
    assert len(sk) == 32

    skM, skX, pkM, pkX = expandDecapsulationKey(sk)
    
    g = GroupP384()
    ctM = ct[0:1568]
    ctXbytes = ct[1568:1617]

    ctX = g.deserialize(ctXbytes)
    
    ssM = mlkem.Dec(skM, ctM, mlkem.params1024)
    
    ssXbase = skX * ctX
    xCoord = ssXbase[0] # X-coordinate
    ssX = I2OSP(xCoord, 48)

    return Combiner(ssM, ssX, ctXbytes, pkX)

class QSFMLKEM1024P384(KEM):
    def __init__(self):
        KEM.__init__(self, label)

    def Nseed(self):
        return 32
    
    def Nrandomness(self):
        return 104
    
    def Npk(self):
        return 1617
    
    def Nsk(self):
        return 32
    
    def Nct(self):
        return 1617
    
    def KeyGen(self):
        return GenerateKeyPair()

    def DeriveKey(self, seed):
        return DeriveKeyPair(seed)
    
    def Encaps(self, pk):
        randomness = os.urandom(80)
        return EncapsulateDerand(pk, randomness)
    
    def EncapsDerand(self, pk, randomness):
        return EncapsulateDerand(pk, randomness)
    
    def Decaps(self, sk, ct):
        return Decapsulate(ct, sk)

if __name__ == "__main__":
    sk, pk = GenerateKeyPair()