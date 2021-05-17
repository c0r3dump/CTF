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

The output of our [solver script](solve.py) is the following:

```bash
> python solve.py
Period for 4 is 7
Period for 4 is 6
Period for 4 is 7
Period for 4 is 6
Period for 4 is 7
Period for 4 is 7
Period for 4 is 7
Period for 4 is 1
Period for 4 is 7
Period for 4 is 7
Period for 5 is 7
Period for 5 is 2
Period for 5 is 15
Period for 5 is 15
Period for 5 is 15
Period for 5 is 15
Period for 5 is 8
Period for 5 is 12
Period for 5 is 4
Period for 5 is 2
Period for 6 is 1
Period for 6 is 28
Period for 6 is 8
Period for 6 is 31
Period for 6 is 28
Period for 6 is 31
Period for 6 is 28
Period for 6 is 31
Period for 6 is 8
Period for 6 is 10
b'Look, a new flag: ptm'
-33653088377663776192109104 -50952268972205221877234096 -6658610176590470404853021 1036253257551142714799835
1036253257551142714799835 35
Built fcsr
b'Look, a new flag: ptm{n0w_r3p0r7_7h3_53c0nd_un1n73nd3d_70_@mr96_1cdf85df0860893c}'
```

The flag is `ptm{n0w_r3p0r7_7h3_53c0nd_un1n73nd3d_70_@mr96_1cdf85df0860893c}`.

### Files

- [solve.py](solve.py)
- [fcsr_solver.py](fcsr_solver.py)
- [fcsr.py](fcsr.py)