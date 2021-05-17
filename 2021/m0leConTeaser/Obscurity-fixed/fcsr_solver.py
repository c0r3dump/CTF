from binascii import hexlify, unhexlify
from sage.all import gcd
from pwnlib.util.fiddling import xor, bits, bitswap, unbits
from fcsr import FCSR, get_test
import math

def run():
    ct = b''
    pt = unhexlify(b'89504e470d0a1a0a0000000d494844520000')
    with open("encrypted_png", "rb") as f:
        ct = f.read()

    key = xor(ct[:8], pt, 'min')
    a_stream = bits(key)[::-1]
    print(b'ct: ' + hexlify(ct[:8]))
    print(b'pt: ' + hexlify(pt))
    print(b'key: ' + hexlify(key))
    print(f'a_stream: {a_stream}')

    q = 2
    while q < 2000:
        print(f'q: {q}')
        m = 0
        k = int(math.log(q, 2))
#        print(f'k: {k}')
#        print(f'a_stream: {a_stream[-k:]}')
        a = 0
        for bit in a_stream[-k:]:
            a = (a << 1) | bit
        while m < 2000:
            generator = FCSR(q, m, a)
            encrypted = generator.encrypt(ct[:8])
#            print(hexlify(encrypted))
#            print(hexlify(pt))
            if encrypted == pt:
                print(f'q: {q}')
                print(f'm: {m}')
                print(f'a: {a}')
                exit()
            m += 1
        q += 1


def phi(x1,x2):
    return max([abs(x1), abs(x2)])
    return abs(x2) if abs(x1) < abs(x2) else abs(x1)

def minim(l, s):
    s1, s2 = s
    l1, l2 = l
    ds = []
    if s1 != s2:
        d = (l1-l2)//(s1-s2)
        ds.append(d)
        ds.append(d+1)
        ds.append(d-1)
        ds.append(d+2)
        ds.append(d-2)
    if s1 != -s2:
        d = -(l1+l2)//(s1+s2)
        ds.append(d)
        ds.append(d+1)
        ds.append(d-1)
        ds.append(d+2)
        ds.append(d-2)
    ds = [d for d in ds if d % 2 ==1]
    minphi = phi(l1+ds[0]*s1, l2+ds[0]*s2)
    mind = ds[0]
    for d in ds[1:]:
        p = phi(l1+d*s1, l2+d*s2)
        if p < minphi:
            minphi = p
            mind = d
    return mind



def small_fcsr_finder(a):
    for i in range(len(a)):
        if a[i] == 1:
            k = i+1
            break
    alpha = a[k-1]*2**(k-1)
    f1, f2 = 0,2
    g1, g2 = 2**(k-1), 1
    while k < len(a):
        #print(f1, f2, g1, g2)
        alpha = alpha + a[k]*2**k
        if (alpha*g2 - g1) % 2**(k+1) == 0:
            f1, f2 = 2*f1, 2*f2
        else:
            if phi(g1,g2) < phi(f1, f2):
                d = minim((f1, f2), (g1, g2))
                t1, t2 = g1, g2
                g1 = f1 + d*g1
                g2 = f2 + d*g2
                f1, f2 = 2*t1, 2*t2
            else:
                d = minim((g1, g2), (f1, f2))
                g1 = g1 + d*f1
                g2 = g2 + d*f2
                f1, f2 = 2*f1, 2*f2
        k += 1
    print(f1, f2, g1, g2)
    return g1,g2

def small_fcsr(a_stream, validation = None):
    p, q = small_fcsr_finder(a_stream)
    p, q = p//gcd(p,q), q//gcd(p,q)
    p, q = abs(int(p)), abs(int(q))
    r = q.bit_length()-1
    y = 0
    for i in range(r):
        for j in range(i+1):
            if j ==0:
                y -= 1
            else:
                y += int(bin(q)[2:][-j-1])*2**i
    m = (y-p) % 2**r
    a = int(''.join(map(str, a_stream[:r][::-1])), 2)
    fcsr = FCSR(q, 0, a)
    #print(q, len(a_stream))
    if validation:
        print("validating")
    for m in range(q):
        fcsr = FCSR(q,m,a)
        if not validation:
            check = fcsr.encrypt(b'\0'*(len(a_stream)//8))
            if bits(check) == a_stream:
                print(q, m)
                return FCSR(q,m,a)
        else:
            full_a = a_stream+validation
            check = fcsr.encrypt(b'\0'*(len(full_a)//8))
            if bits(check) == full_a:
                print("validated", q,m)
                return FCSR(q,m,a)
    assert("unreachable")

def run2():
    ct = b''
    pt = unhexlify(b'89504e470d0a1a0a0000000d494844520000')
    with open("encrypted_png", "rb") as f:
        ct = f.read()

    key = xor(ct[:8], pt, cut='min')
    a_stream = bits(key)
    print(b'ct: ' + hexlify(ct[:8]))
    print(b'pt: ' + hexlify(pt))
    print(b'key: ' + hexlify(key))
    print(f'a_stream: {a_stream}')
    p, q = small_fcsr_finder(a_stream)
    print(f'p: {bin(p)} {p}')
    print(f'q: {bin(q)} {q}')
    p, q = p//gcd(p,q), q//gcd(p,q)
    p, q = abs(int(p)), abs(int(q))
    print(p,q)
    r = q.bit_length()-1
    y = 0
    for i in range(r):
        for j in range(i+1):
            if j ==0:
                y -= 1
            else:
                y += int(bin(q)[2:][-j-1])*2**i
    m = (y-p) % 2**r
    print(f'm: {m}')
    a = int(''.join(map(str, a_stream[:r][::-1])), 2)
    fcsr = FCSR(q, 0, a)
    fd = open('encrypted_png', 'rb')
    data = fd.read()
    fd.close()

    encrypted_png = fcsr.encrypt(data)

    fd = open('decrypted.png', 'wb')
    fd.write(encrypted_png)
    fd.close()
    fcsr = FCSR(q, 0, a)
    a_ = fcsr.encrypt(b'\0'*8)
    print(a_)
    for m in range(q):
        fcsr = FCSR(q,m,a)
        check = fcsr.encrypt(b'\0'*8)
        if bits(check) == a_stream[:64]:
            print('done', m)
            fcsr = FCSR(q,m,a)
            fd = open('encrypted_png', 'rb')
            data = fd.read()
            fd.close()

            encrypted_png = fcsr.encrypt(data)

            fd = open('decrypted.png', 'wb')
            fd.write(encrypted_png)
            fd.close()
            
            
    breakpoint()

def test():
    f, enc, q_orig, a_orig = get_test()
    print(a_orig)
    
    key = xor(f[:8], enc, cut='min')
    print(key)
    a_stream = bits(key)
    print(a_stream)
    print(bin(a_orig))
    p, q = small_fcsr_finder(a_stream)
    p, q = p//gcd(p,q), q//gcd(p,q)
    p, q = abs(int(p)), abs(int(q))
    print(bin(p))
    print(bin(q))
    print(p,q)
    r = q.bit_length()-1
    a = int(''.join(map(str, a_stream[:r][::-1])), 2)
    fcsr = FCSR(q, 0, a)

    decrypted = fcsr.encrypt(enc)
    print(decrypted == f)
    breakpoint()

if __name__ == "__main__":
    png = open("encrypted_png", "rb").read()
    #run()
    run2()
    #test()
