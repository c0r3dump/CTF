# m0leCon 2021 CTF Teaser - babysign

## Challenge

It's just a warmup, don't take it too seriously.

`nc challs.m0lecon.it 7012`

[server.py](server.py)

### Metadata

- Tags: `crypto`, `warmup`
- Author: *mr96*
- Points: 88
- Solves: 71

## Solution

Get `N`,`e` using `4)` then using `2)` send a character 64 times to make sure the `sha256` used to `xor` is just `sha256(32 times the character)`.

Flag: ``