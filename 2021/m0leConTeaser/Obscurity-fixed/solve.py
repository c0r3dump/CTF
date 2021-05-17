import random
from functools import reduce
from pwnlib.util.fiddling import xor, bits, bitswap, unbits
from fcsr_solver import small_fcsr
from pwn import remote
from hashlib import sha256

def proof_of_work(p):
    d = p.recvline()
    print(d)
    d = d.split()
    start = d[6]
    end = d[13][:-1].decode("ascii")
    print(start, end)
    a = bytearray(start) + b'\x61'*8
    s = 0
    while not sha256(a).digest().hex().endswith(end):
        i = -1
        if s % 2**16 == 0:
            print(a)
            print(s)
        while a[i] >= 122:
            a[i] = 97
            i -= 1
        a[i] += 1
        s += 1
    p.sendline(a)

def xor(a, b):
    return bytes(x^y for x,y in zip(a,b))

class LFSR(object):
    def __init__(self, s, p):
        self.s = s
        self.p = p

    def clock(self):
        out = self.s[0]
        self.s = self.s[1:]+[self.s[0]^self.s[(self.p)[0]]^self.s[(self.p)[1]]]
        return out

def buildLFSR(l):
    return LFSR([int(x) for x in list(bin(random.randint(1,2**l-1))[2:].rjust(l,'0'))], random.sample(range(1,l), k=2))


def test_period(i):
    for _ in range(10):
        l = buildLFSR(i)
        bits = [l.clock() for _ in range(200)]
        for j in range(1,62):
            if bits[62:120] == bits[62+j:120+j]:
                print(f"Period for {i} is {j}")
                break

test_period(4)
test_period(5)
test_period(6)
pt = "Look, a new flag: ptm"# + flag
pt = pt.encode()

def build_chall(n):
    #pt = "Look, a new flag: " + flag
    #pt = pt.encode()

    lfsr_len = [random.randint(4,6) for _ in range(random.randint(9,12))]
    L = [buildLFSR(i) for i in lfsr_len]
    u = 0
    key = b""
    bits = []
    for i in range(n):
        ch = 0
        for j in range(8):
            outvec = [l.clock() for l in L]
            out = (reduce(lambda i, j: i^j, outvec) ^ u) & 1
            u = (u+sum(outvec))//2
            ch += out*pow(2,7-j)
            bits.append(out)
        key += bytes([ch])

    res = xor(key,pt).hex()
    return bits


'''
for _ in range(10):
    bits = build_chall(len(pt)*8*2)
    f = small_fcsr(bits[:len(pt)*8], validation = bits[len(pt)*8:])
'''
def solve_second():
    data = bytes.fromhex(open("output.txt").read())
    known = xor(data[:len(pt)], pt)

    b = bits(xor(data[:len(pt)], pt))
    print(xor(data[:len(pt)], unbits(b)))
    assert(unbits(bits(data[:len(pt)])) == data[:len(pt)])

    #fcsr = small_fcsr(b[:-8], b[-8:])
    fcsr = small_fcsr(b)
    #b1 = [fcsr.clock() for _ in b]
    #print(xor(data[len(pt):], unbits(b1)))
    print("Built fcsr")

    #dec = fcsr.encrypt(data)
    b1 = [fcsr.clock() for _ in range(len(data)*8)]
    dec = xor(unbits(b1), data)

    print(dec)

def solve_first():
    p = remote("challs.m0lecon.it", 2561)
    proof_of_work(p)
    ptt = b'0'*18 #+pt
    p.sendline(ptt.hex())
    print(p.recvline())
    data = bytes.fromhex(p.recvline().strip().decode('ascii'))
    print("Response:", data)
    ptt = ptt
    b = bits(xor(data[:len(ptt)], ptt))
    #fcsr = small_fcsr(b[:-8], b[-8:])
    fcsr = small_fcsr(b)
    print("Built fcsr")

    b1 = [fcsr.clock() for _ in range(len(data)*8)]
    assert(b == b1[:len(b)])
    dec = xor(unbits(b1), data)
    print("Decrypted data", dec)


#solve_first()
solve_second()
