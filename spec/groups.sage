#!/usr/bin/sage
# vim: syntax=python

import random
import hashlib
from util import I2OSP, OS2IP

def sgn0(x):
    """
    Returns 1 if x is 'negative' (little-endian sense), else 0.
    """
    degree = x.parent().degree()
    if degree == 1:
        # not a field extension
        xi_values = (ZZ(x),)
    else:
        # field extension
        xi_values = ZZR(x)  # extract vector repr of field element (faster than x._vector_())
    sign = 0
    zero = 1
    # compute the sign in constant time
    for i in range(0, degree):
        zz_xi = xi_values[i]
        # sign of this digit
        sign_i = zz_xi % 2
        zero_i = zz_xi == 0
        # update sign and zero
        sign = sign | (zero & sign_i)
        zero = zero & zero_i
    return sign

# Fix a seed so all test vectors are deterministic
FIXED_SEED = "test".encode('utf-8')
random.seed(int.from_bytes(hashlib.sha256(FIXED_SEED).digest(), 'big'))

class Group(object):
    def __init__(self, name):
        self.name = name

    def generator(self):
        raise Exception("not implemented")

    def identity(self):
        raise Exception("not implemented")

    def order(self):
        raise Exception("not implemented")

    def serialize(self, element):
        raise Exception("not implemented")

    def deserialize(self, encoded):
        raise Exception("not implemented")

    def serialize_scalar(self, scalar):
        raise Exception("not implemented")

    def element_byte_length(self):
        raise Exception("not implemented")

    def scalar_byte_length(self):
        raise Exception("not implemented")

    def random_scalar(self):
        return random.randint(0, self.order() - 1)

    def random_nonzero_scalar(self):
        return random.randint(1, self.order() - 1)

    def __str__(self):
        return self.name

class GroupNISTCurve(Group):
    def __init__(self, name, F, A, B, p, order, gx, gy):
        Group.__init__(self, name)
        self.F = F
        EC = EllipticCurve(F, [F(A), F(B)])
        self.curve = EC
        self.p = p
        self.a = A
        self.b = B
        self.group_order = order
        self.G = EC(F(gx), F(gy))
        self.field_bytes_length = int(ceil(self.p.nbits() / 8))

    def generator(self):
        return self.G

    def order(self):
        return self.group_order

    def identity(self):
        return self.curve(0)

    def serialize(self, element):
        if element == self.identity():
            raise Exception("Identity element not permitted")

        x, y = element[0], element[1]
        sgn = sgn0(y)
        byte = 2 if sgn == 0 else 3
        return I2OSP(byte, 1) + I2OSP(x, self.field_bytes_length)

    # this is using point compression
    def deserialize(self, encoded):
        # 0x02 | 0x03 || x
        pve = encoded[0] == 0x02
        nve = encoded[0] == 0x03
        assert(pve or nve)
        assert(len(encoded) % 2 != 0)
        x = OS2IP(encoded[1:])
        y2 = x^3 + self.a*x + self.b
        y = y2.sqrt()
        parity = 0 if pve else 1
        if sgn0(y) != parity:
            y = -y
        point = self.curve(self.F(x), self.F(y))

        if point == self.identity():
            raise Exception("Identity element not permitted")

        return point

    def serialize_scalar(self, scalar):
        return I2OSP(scalar % self.order(), self.scalar_byte_length())

    def element_byte_length(self):
        return int(1 + self.field_bytes_length)

    def scalar_byte_length(self):
        return int(self.field_bytes_length)


class GroupP256(GroupNISTCurve):
    def __init__(self):
        # See FIPS 186-3, section D.2.3
        p = 2^256 - 2^224 + 2^192 + 2^96 - 1
        F = GF(p)
        A = F(-3)
        B = F(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
        order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
        gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
        gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
        GroupNISTCurve.__init__(self, "P-256", F, A, B, p, order, gx, gy)

class GroupP384(GroupNISTCurve):
    def __init__(self):
        # See FIPS 186-3, section D.2.3
        p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff
        F = GF(p)
        A = F(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc)
        B = F(0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef)
        order = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973
        gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7
        gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f
        GroupNISTCurve.__init__(self, "P-384", F, A, B, p, order, gx, gy)

if __name__ == "__main__":
    g = GroupP256()
    print(g)
    g = GroupP384()
    print(g)