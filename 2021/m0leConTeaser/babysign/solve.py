from pwn import remote
from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha256

from string import ascii_letters

def proof_of_work():
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

p = remote('challs.m0lecon.it', 7012)

proof_of_work()

for _ in range(6):
    print(p.recvline())
p.sendline(b"4")
N = int(p.recvline().strip()[3:])
e = int(p.recvline().strip()[3:])
assert(e == 65537)
print(N,e)

for _ in range(6):
    print(p.recvline())
p.sendline("2")
p.sendline(b"1"*64)
sign = int(p.recvline().strip(), 16)

xored = pow(sign, e, N)
orig = bytes_to_long(sha256(b"1"*32).digest())^xored
print(long_to_bytes(orig))
