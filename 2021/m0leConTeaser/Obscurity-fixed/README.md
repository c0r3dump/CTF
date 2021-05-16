# m0leCon 2021 CTF Teaser - Obscurity-fixed

## Challenge

As before, but static!

[chall.py](chall.py), [output.txt](output.txt)

### Metadata

- Tags: `crypto`
- Author: *mr96*
- Points: 469
- Solves: 2

## Solution

The algorithm resembles an `FCSR`, so I used the smallest FCSR algorithm by Klapper and Goresky. Using the bits just from the `Look, a new flag: ` shown in the challenge script did not work, however adding the flag format, `Look, a new flag: ptm{`, got the flag.

The flag is `ptm{n0w_r3p0r7_7h3_53c0nd_un1n73nd3d_70_@mr96_1cdf85df0860893c}`.