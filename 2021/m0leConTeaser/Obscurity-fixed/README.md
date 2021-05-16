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

Flag: ``