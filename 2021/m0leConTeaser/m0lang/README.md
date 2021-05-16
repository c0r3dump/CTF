# m0leCon 2021 CTF Teaser - m0lang

## Challenge

A friend of mine developed this brand new interpreter, do you want to play with it?

[chall](chall)

### Metadata

- Tags: `reverse`
- Author: *matpro*
- Points: 406
- Solves: 5

## Solution

Solution: `help "help"; flag;`

The help text of the command `help` is longer than it seems, and it decrypts the flag too. After it's decrypted, we have to retrieve it in the same command in order to avoid it being reset in `refresh()`.

```bash
./chall 
m0lang 0.1 (May 14 2021, 19:00:00)
Type 'help "<command>"' or 'help <value>' for more information.
m0lang> help "help"; flag;
Really? You need help for help?
This is the flag: ptm{c4n_U_r34lly_1nt3rpret_Thi5_flag?}, now you can submit it!
m0lang> 
```

The flag is `ptm{c4n_U_r34lly_1nt3rpret_Thi5_flag?}`.