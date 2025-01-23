# WARNING This is a specification of the KEM API; not a production-ready implementation.

class KEM(object):
    def __init__(self, name):
        self.name = name

    def Nseed(self):
        
        raise Exception("not implemented")
    
    def Neseed(self):
        raise Exception("not implemented")
    
    def Npk(self):
        raise Exception("not implemented")
    
    def Nsk(self):
        raise Exception("not implemented")
    
    def Nct(self):
        raise Exception("not implemented")

    def KeyGen(self):
        raise Exception("not implemented")

    def DeriveKey(self, seed):
        raise Exception("not implemented")
    
    def Encaps(self, pk):
        raise Exception("not implemented")
    
    def EncapsDerand(self, pk, eseed):
        raise Exception("not implemented")
    
    def Decaps(self, sk, ct):
        raise Exception("not implemented")
