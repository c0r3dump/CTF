# m0leCon 2021 CTF Teaser - PeTaMorhposis

## Challenge

Just another rev.

[chall](chall), [out](out)

### Metadata

- Tags: `reverse`
- Author: *a_sin*
- Points: 179
- Solves: 25

## Solution

### About the challenge

After some reversing, I found that the challenge does the following:

- 0. Read the contents of `flag.txt`
- 1. Apply some functions to each byte individually, depending on the index of that character in the flag.
- 2. Permutate the characters of the flags
- 3. Apply some functions to each byte individually, depending on the index of that character in the flag.
- 4. Write the result into `out.txt` (the organizers were kind enough to hand out the correct output as `out`, so that we don't accidentally overwrite it when running `chall`).

Note that the functions applied in step 1 and 3 look the same at first sight, because they are at the same memory address. However, between those two events, the program modifies its own code, so in the end, the operations applied in step 1 and 3 are different.

### Solution

We just have to invert the operations and the permutation. Inverting the permutation is trivial, and reversing the operations is also pretty easy.

- Operations used in the first step: `x = x ^ 0x99`; `x = x + 0x19`; `x = x - 0x3`
- Operations used in the third step: `x = shl(x, 1)`; `x = rol(x, 5)`; `x = x ^ 0x21`

All of these operations are invertible, except `shl`; if you know `shl(x, 1)`, you can only get back 7 bits of `x`, because the most significant bit was shifted out. Hence some guessing is required to correctly invert this operation. Using the fact that the flag should look like `ptm{s0m3_1337_str1ng}`, you can see that which character is wrong, and flip the MSB of the corresponding byte when inverting the bit shift. Note that the bit shift occurs after the permutation, so you have to take that into account when finding out which bit you want to flip. In the solver script, `SHIFT_MSB` corresponds to the bytes of the plaintext flag, and `SHIFT_MSB_PERM` corresponds to the bytes of the permutated flag. Note that the solver script uses `SHIFT_MSB_PERM` when determining the MSB, but you should only edit `SHIFT_MSB` when you try to find the correct values. This makes it easy to find the solution, because you don't have to worry about the permutation (e.g. if you see that the flag starts with `p\xf4m{`, then you know that the character at index `1` is probably wrong, so you have to flip the `SHIFT_MSB[1]` bit).

### Solver program

```python
import struct
PERMUTATION = struct.pack ("39B", *[
0x12,0x02,0x07,0x0d,0x14,0x1d,0x10,0x09,0x11,0x1a,0x05,
0x00,0x1f,0x0a,0x26,0x17,0x23,0x03,0x21,0x16,0x0c,0x19,
0x25,0x15,0x0f,0x24,0x06,0x1c,0x08,0x22,0x0b,0x1e,0x1b,
0x0e,0x01,0x04,0x13,0x18,0x20])

INVERSE_PERMUTATION = [0]*0x27

SHIFT_MSB = [0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1]

for (i, p) in enumerate(PERMUTATION):
    INVERSE_PERMUTATION[p] = i

SHIFT_MSB_PERM = []
for i in range(0x27):
    SHIFT_MSB_PERM.append(SHIFT_MSB[INVERSE_PERMUTATION[i]])

print(SHIFT_MSB_PERM)

with open("out", "rb") as f:
    enc_flag = list(f.read())

for i in range(len(enc_flag)):
    i3 = i % 3
    if i3 == 0:
        enc_flag[i] = ((enc_flag[i] >> 5) | (enc_flag[i] << 3)) & 0xff
    else:
        # NOTE: shl is not invertible, MSB could either be one or zero
        enc_flag[i] = (enc_flag[i] >> 1) & 0xff
        enc_flag[i] |= SHIFT_MSB_PERM[i] << 7
        # enc_flag[i] |= 0x80
        if i3 == 1:
            enc_flag[i] ^= 0x21

print(list(map(hex, enc_flag)))

unpermuted_flag = []
for i in range(len(enc_flag)):
    unpermuted_flag.append(enc_flag[PERMUTATION[i]])

enc_flag = unpermuted_flag
print(list(map(hex, enc_flag)))

for i in range(len(enc_flag)):
    i3 = i % 3
    if i3 == 0:
        enc_flag[i] = (enc_flag[i]-0x19) & 0xff
    else:
        enc_flag[i] ^= 0x99
        if i3 == 1:
            enc_flag[i] = (enc_flag[i]+0x3) & 0xff


print(list(map(hex, enc_flag)))
print(bytes(enc_flag))

with open('flag.txt', 'wb') as f:
    f.write(bytes(enc_flag))
```

If we run this script, we get the flag:

```bash
> python solve.py 
[0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1]
['0xfd', '0xf9', '0xe8', '0xfe', '0xa9', '0xb4', '0xf7', '0xf4', '0xc5', '0xfa', '0xfa', '0x81', '0xa9', '0x94', '0x78', '0x4a', '0x85', '0xc6', '0x89', '0x49', '0xe9', '0xc6', '0xf9', '0x4a', '0xf0', '0x7d', '0x86', '0xed', '0x8d', '0xaa', '0xa8', '0x4a', '0xe4', '0x78', '0xed', '0xf2', '0xe9', '0xa9', '0xe0']
['0x89', '0xe8', '0xf4', '0x94', '0xe9', '0xaa', '0x85', '0xfa', '0xc6', '0x86', '0xb4', '0xfd', '0x4a', '0xfa', '0xe0', '0x4a', '0xf2', '0xfe', '0x78', '0xf9', '0xa9', '0x7d', '0xa9', '0xc6', '0x4a', '0xe9', '0xf7', '0x8d', '0xc5', '0xed', '0x81', '0xa8', '0xed', '0x78', '0xf9', '0xa9', '0x49', '0xf0', '0xe4']
['0x70', '0x74', '0x6d', '0x7b', '0x73', '0x33', '0x6c', '0x66', '0x5f', '0x6d', '0x30', '0x64', '0x31', '0x66', '0x79', '0x31', '0x6e', '0x67', '0x5f', '0x63', '0x30', '0x64', '0x33', '0x5f', '0x31', '0x73', '0x6e', '0x74', '0x5f', '0x74', '0x68', '0x34', '0x74', '0x5f', '0x63', '0x30', '0x30', '0x6c', '0x7d']
b'ptm{s3lf_m0d1fy1ng_c0d3_1snt_th4t_c00l}'
```

The flag is `ptm{s3lf_m0d1fy1ng_c0d3_1snt_th4t_c00l}`.

### Files

- [solve.py](solve.py)