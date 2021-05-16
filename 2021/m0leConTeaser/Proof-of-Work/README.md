# m0leCon 2021 CTF Teaser - Proof-of-Work

## Challenge

Hello Hacker!

In this challenge you simply need to solve a proof-of-work. The proof-of-work will be the same for most of the challenges, so we provide you with a template in Python to solve it. Simply run it to get this flag.

This solver is not the fastest possible, so you can write your own, but you won't receive any support on it.

You can solve the challenge manually at:

`nc challs.m0lecon.it 1337`

Happy Hacking!

[pow-template.py](pow-template.py)

### Metadata

- Tags: `misc`, `warmup`
- Author: -
- Points: 57
- Solves: 264

## Solution

We just have to execute the given PoW script:

```
python pow_template.py
[+] Opening connection to challs.m0lecon.it on port 1337: Done
Solving PoW...
Solved!
[*] Switching to interactive mode
ptm{w3lc0me_t0_m0lecon_2021_t34ser_ctf_chall3ng3_++++}
[*] Got EOF while reading in interactive
```

The flag is `ptm{w3lc0me_t0_m0lecon_2021_t34ser_ctf_chall3ng3_++++}`.