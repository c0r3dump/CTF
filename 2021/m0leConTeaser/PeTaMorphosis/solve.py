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