# SpamAndFlags 2020 - OTS

## Challenge

That's right, we have not one, not three, but TWO projects focused on post quantum cryptography. Our newest product will surely make a killing. Unlike measily RSA, we are dead sure you can't break this one, not even with your fancy quantum computers.

More info on: `nc 34.89.64.81 1337`

105 points

## Solution

When connecting to the server we receive a message: `My favorite number is 3417798650350847801.` (the number is different each time we connect), its signature, the code used for signing, and the public key.

```python
class OTS:
    def __init__(self):
        self.key_len = 128
        self.priv_key = secrets.token_bytes(16*self.key_len)
        self.pub_key = b''.join([self.hash_iter(self.priv_key[16*i:16*(i+1)], 255) for i in range(self.key_len)]).hex()
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
```

The signing is a simple hash iterator. If our message's `ith` byte is `n`, then the signature's `[i*16,(i+1)*16)` bytes will be the result of `255-n` times md5 hashing the private key's `[i*16,(i+1)*16)` bytes. The only twist is the message we send will be padded to 112 bytes using zeroes and concatenated with the md5 hash of this byte array.

The weakness of an iterator like this, is that if we know the signature of byte `n` at the `ith` position then we know the signature of every `k <= n` byte at the `ith` position, since `sign(k) = hash_iter(private[i*16,(i+1)*16], 255-k) = hash_iter(hash_iter(private[i*16,(i+1)*16], 255-n), n - k)`. So without the md5 hash at the end, all we would have to do is to find 4 bytes in an interval that are bigger then bytes in `flag`, replace them with `flag` and iterate the corresponding parts of the signature.

The "twist" is that our md5 hash has to be smaller at every byte than the md5 hash of the signed message. This can be done by trying many different messages: We lower arbitrary bytes of the message except the `flag` bytes until we find a hash that is suitable. With 16 bytes the probability of an md5 hash being lower at every byte than the other rarely goes below `1e-10`, but we can easily fish for messages from the server where this probability is `1e-7` (the bytes of the signed messages hash are big).

Basically:
- We generate an input that has 'flag' in it and has smaller byte at every index than the known, signed message. 
- Then we iterate the md5 hash to the ith byte `signed[i] - new[i]` times and get the signature of the new message.

The flag is `SaF{better_stick_with_WOTS+}`.

## Files

- [Solution](solve.py)

## Other write-ups

- <https://ctftime.org/task/11519>
