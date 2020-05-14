from pwn import *
import pdb
import hmac

class OTS:
    def __init__(self):
        self.key_len = 128
        #self.priv_key = secrets.token_bytes(16*self.key_len)
        #self.pub_key = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255) for i in range(self.key_len)]).hex()
        self.pub_key = pub_key

    def hash_iter(self, msg, n):
        assert len(msg) == 16
        assert(n >= 0)
        print('iter', n)
        for i in range(n):
            msg = hashlib.md5(msg).digest()
        return msg

    def wrap(self, msg):
        raw = msg.encode('utf-8')
        assert len(raw) <= self.key_len - 16
        raw = raw + b'\x00'*(self.key_len - 16 - len(raw))
        raw = raw + hashlib.md5(raw).digest()
        return raw

    def sign(self, msg):
        raw = self.wrap(msg)
        signature = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255-raw[i]) for i in range(len(raw))]).hex()
        self.verify(msg, signature)
        return signature

    def verify(self, msg, signature):
        raw = self.wrap(msg)
        signature = bytes.fromhex(signature)
        assert len(signature) == self.key_len * 16
        calc_pub_key = b''.join([self.hash_iter(signature[16*i:16*(i+1)], raw[i]) for i in range(len(raw))]).hex()
        assert hmac.compare_digest(self.pub_key, calc_pub_key)

    def transformSig(self, signed, signature, new): 
        self.verify(signed, signature)
        origNew = new
        signed = self.wrap(signed)
        print('signed:',signed)
        new = bytearray(self.wrap(new)[:-16])
        signature = bytes.fromhex(signature)
        sigHash = signed[-16:]
        chance = 1.0
        for i in sigHash:
            chance *= (i+1)/256
        print(chance, 1/chance)
        for b1, b2 in zip(signed[:-16], new):
            assert(b1 >= b2)
        for i in range(20):
            print(signed[i])
        print('newlen', len(new))
        for i0 in range(32,signed[0]+1):
            new[0] = i0
            for i1 in range(32,signed[1]+1):
                new[1] = i1
                for i2 in range(32, signed[2]+1):
                    new[2] = i2
                    for i3 in range(32, signed[3]+1):
                        new[3] = i3
                        for i4 in range(32, signed[4]+1):
                            new[4] = i4
                            for i9 in range(32,signed[9]+1):
                                new[9] = i9
                                for i10 in range(32, signed[10]+1):
                                    new[10] = i10
                                    newHash = hashlib.md5(new).digest()
                                    for o, n in zip(sigHash, newHash):
                                        if o < n:
                                            break
                                    else:
                                        new += newHash
                                        print('iterating sign')
                                        newSig = b''.join([self.hash_iter(signature[16*i:16*(i+1)], signed[i] - new[i]) for i in range(len(new))]).hex()
                                        print(new)
                                        print('verifying sign')
                                        sol = new[:len(origNew)].decode('utf-8')
                                        self.verify(sol, newSig)
                                        return sol, newSig

p = remote('34.89.64.81', 1337)

print(p.recvuntil(b'pub_key = '))
print(p.recvuntil(b'pub_key = '))
print(p.recvuntil(b'pub_key = '))

pub_key = p.recvline().strip().decode('utf-8')
assert(len(pub_key) == 16*128*2)

print(pub_key)
print(p.recvuntil('"'))

signedStr = p.recvuntil('"')[:-1].decode('utf-8')
ourStr = signedStr[:5] + 'flag' + signedStr[9:]

print(signedStr)
print(p.recvuntil(b' = '))

knownsig = p.recvline().strip().decode('utf-8')
print(knownsig)
assert(len(knownsig) == 16*128*2)

print(p.recvline())
print(p.recvline())

ots = OTS()
msg, sig = ots.transformSig(signedStr, knownsig, ourStr)
print(sig)
p.sendline(msg)
print(p.recvline())
p.sendline(sig.encode('utf-8'))
print(p.recvall())
