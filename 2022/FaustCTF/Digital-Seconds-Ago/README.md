# Faust CTF 2022 - Digital Seconds Ago

## Description

The challenge consists of a single ELF binary called `digital-seconds-ago`, which runs as a systemd service.

## Analysis of the binary

After analyzing the binary, you can see that it uses a database, which is created via the following SQL command:

```sql
CREATE TABLE IF NOT EXISTS users(uid INTEGER PRIMARY KEY, name TEXT, pubkey  TEXT, profile TEXT);
```

After the database is created, the service provides the following actions:

- Register: give a username, a public key and a profile, which will be stored in the database.
- Login: give a username, then get a challenge (a few random bytes); if you can sign the challenge with your private key (that corresponds to the public key given at registration), then the login is successful, and you can read the profile.
- Users: print the list of users in the database
- Pubkey: prints the public key of the given user
- Help: prints the help
- Exit: exits the program

## Where are the flags?

The flags are in the `profile` field of the database. In each round, the organizers register a new user with the `profile` being the flag.

## Getting the flags

If you successfully login, then the profile of that user is printed; but in order to log in, you need to find a vulnerability in the cryptographic system that checks the signature. This was the harder way to solve a challenge, but there was a shortcut hidden in the binary.

The `main(0x22d0)` function reads a line, checks if it matches one of the actions mentioned before, and if it does, it calls the handler function for that action. However, there is an extra check, which is in a function called by `main`, let's call it `check_backdoor(0x3810)`. Here is the decompiled version of the function:

```c
undefined8 check_backdoor(char *command)

{
  long lVar1;
  size_t command_len;
  undefined8 uVar2;
  undefined8 uVar3;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  command_len = strlen(command);
  uVar3 = 0;
  uVar2 = 0;
  if ((((((command_len == 0xc) && (*command != command[1])) && (command[2] != command[5])) &&
       ((uVar3 = uVar2, command[3] != command[4] && (*command == command[0xb])))) &&
      ((command[1] == command[10] && ((command[2] == command[9] && (command[3] == command[8]))))))
     && (command[4] == command[7])) {
    if (command[5] == command[6]) {
      puts("... ok, but only 2 past seconds");
      uVar3 = 1;
    }
    else {
      uVar3 = 0;
    }
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

We can see that this function returns `1` if the following conditions are met:

- The `command` is 12 characters long
- The `command` is a palindrome word
- There are no identical characters in the first six letters of `command`

It is really easy to come up with a solution, for example: `"abcdeffedcba"`.

Looking back at the `main` function, we see that if we pass the check, it will call another function:

```c
      iVar1 = check_backdoor(input);
      if (iVar1 != 0) {
        do_backdoor();
        goto LAB_001023b0;
      }
```

The `do_backdoor(0x38c0)` function runs the following SQL query:

```sql
"SELECT name, profile FROM users ORDER BY uid DESC LIMIT 2"
```

It selects the last two entries in the database (ordered by `uid`), and prints their name and profile. Since the profile contains the flag, we can just read it.

## Summary

The solution is really simple: you just have to send `"abcdeffedcba"`, and then you get two flags.

## Patching the backdoor

Here is the relevant part of the assembly code of the `main` function:

```
            0x000023ff      4889ef         mov rdi, rbp
            0x00002402      e809140000     call check_backdoor
            0x00002407      85c0           test eax, eax
        ┌─< 0x00002409      7545           jne 0x2450                   ; here we jump to the backdoor, if the check succeeded
        │   0x0000240b      83c301         add ebx, 1
        │   0x0000240e      4983c710       add r15, 0x10
        │   0x00002412      83fb06         cmp ebx, 6
        │   0x00002415      75d4           jne 0x23eb
        │   0x00002417      488d3d511f00.  lea rdi, str.unknown_command
        │   0x0000241e      e85dfcffff     call sym.imp.puts
        │   0x00002423      eb8b           jmp 0x23b0
        │   0x00002425      0f1f00         nop dword [rax]
        │   0x00002428      488d3d2c1f00.  lea rdi, str.fail_to_get_command
        │   0x0000242f      e84c030000     call 0x2780
        │   0x00002434      eba8           jmp 0x23de
        │   0x00002436      662e0f1f8400.  nop word cs:[rax + rax]
        │   0x00002440      4863db         movsxd rbx, ebx
        │   0x00002443      48c1e304       shl rbx, 4
        │   0x00002447      ff541c08       call qword [rsp + rbx + 8]
        │   0x0000244b      e960ffffff     jmp 0x23b0
        └─> 0x00002450      31c0           xor eax, eax
            0x00002452      e869140000     call do_backdoor
            0x00002457      e954ffffff     jmp 0x23b0`
```

There are many ways to fix it, e.g. replace the call to `check_backdoor` with `xor eax, eax` (and some `nop`-s), or you can modify the `check_backdoor` and `do_backdoor` functions, too. I chose to replace the conditinonal jump with two `nop`-s so that we never jump to `call do_backdoor`. Here is the modified code:

```
            0x000023ff      4889ef         mov rdi, rbp
            0x00002402      e809140000     call check_backdoor
            0x00002407      85c0           test eax, eax
            0x00002409      90             nop                          ; conditional jump replaced with nops, hence we never jump to `call do_backdoor`
            0x0000240a      90             nop
            0x0000240b      83c301         add ebx, 1
            0x0000240e      4983c710       add r15, 0x10
            0x00002412      83fb06         cmp ebx, 6
            0x00002415      75d4           jne 0x23eb
            0x00002417      488d3d511f00.  lea rdi, str.unknown_command
            0x0000241e      e85dfcffff     call sym.imp.puts
            0x00002423      eb8b           jmp 0x23b0
            0x00002425      0f1f00         nop dword [rax]
            0x00002428      488d3d2c1f00.  lea rdi, str.fail_to_get_command
            0x0000242f      e84c030000     call 0x2780
            0x00002434      eba8           jmp 0x23de
            0x00002436      662e0f1f8400.  nop word cs:[rax + rax]
            0x00002440      4863db         movsxd rbx, ebx
            0x00002443      48c1e304       shl rbx, 4
            0x00002447      ff541c08       call qword [rsp + rbx + 8]
            0x0000244b      e960ffffff     jmp 0x23b0
            0x00002450      31c0           xor eax, eax
            0x00002452      e869140000     call do_backdoor
            0x00002457      e954ffffff     jmp 0x23b0
```
