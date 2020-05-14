# SpamAndFlags 2020 - OTS

## Challenge

That's right, we have not one, not three, but TWO projects focused on post quantum cryptography. Our newest product will surely make a killing. Unlike measily RSA, we are dead sure you can't break this one, not even with your fancy quantum computers.

More info on: `nc 34.89.64.81 1337`

105 points

## Solution

We generate an input that has 'flag' in it and has smaller byte at every index than the known, signed message. 

Then we iterate the md5 hash to the ith byte `signed[i] - new[i]` times and get the signature of the new message.

The flag is `SaF{better_stick_with_WOTS+}`.

## Files

- [Solution](solve.py)

## Other write-ups

- <https://ctftime.org/task/11519>
