from qsf_mlkem768_p256 import *
from qsf_mlkem1024_p384 import *
from kitchensink_mlkem768_x25519 import *

import binascii
import json
import io

from Crypto.Hash import SHAKE128

def hex(s):
    return binascii.hexlify(s).decode('utf-8')

def test_vectors(kems, setVectors = True):
    for kem in kems:
        h = SHAKE128.new()
        ret = []
        for i in range(3):
            seed = h.read(kem.Nseed())
            randomness = h.read(kem.Nrandomness())
            sk, pk = kem.DeriveKey(seed)
            ss, ct = kem.EncapsDerand(pk, randomness)
            ss2 = kem.Decaps(sk, ct)
            assert ss == ss2

            ret.append({
                "seed":  hex(seed),
                "randomness": hex(randomness),
                "ss":    hex(ss),
                "sk":    hex(sk),
                "pk":    hex(pk),
                "ct":    hex(ct),
            })

        fname = 'test-vectors-%s' % kem.name
        if setVectors:
            with open(fname + '.json', 'w') as f:
                f.write(json.dumps(ret))
            with open(fname + '.txt', 'w') as f:
                f.write(dump_vectors(ret))
        else:
            with open(fname + '.json', 'r') as f:
                assert f.read() == json.dumps(ret)
            with open(fname + '.txt', 'r') as f:
                assert f.read() == dump_vectors(ret)

def dump_val(f, name, val):
    f.write(name)
    width = 74
    if len(name) + 5 + len(val) < width:
        f.write('     ')
        f.write(val)
        f.write('\n')
        return
    f.write('\n')
    while val:
        f.write('  ')
        f.write(val[:width-2])
        val = val[width-2:]
        f.write('\n')

def dump_vectors(vecs):
    f = io.StringIO()
    for vec in vecs:
        for k in ['seed', 'sk', 'pk', 'randomness', 'ct', 'ss']:
            dump_val(f, k, vec[k])
        f.write('\n')
    return f.getvalue()

if __name__ == '__main__':
    kems = [
        QSFMLKEM768P256(),
        QSFMLKEM1024P384(),
        KitchenSinkMLKEM768X25519(),
    ]
    test_vectors(kems)
    test_vectors(kems, False)
