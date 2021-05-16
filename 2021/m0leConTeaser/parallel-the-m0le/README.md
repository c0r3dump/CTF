# m0leCon 2021 CTF Teaser - parallel-the-m0le

## Challenge

I was playing with some parallel programming but I'm so bad with it that I lost the flag, can you help me recover it?

Output: `2aad2e5a49fb2d9adb908dd00eb48c8a6607ab619f75b0272f3c1eb33fe9edaf`

[chall](chall)

### Metadata

- Tags: `reverse`
- Author: *spicyNduja*
- Points: 301
- Solves: 11

## Solution

### About the challenge

After some reversing, I found that the challenge does the following:

- Take a 0x10 long input (the flag)
- Apply some operations on it in random order
- Print the result (let's call it `s`)
- Apply the operations in a slightly modified but predictable order again to `s`
- Print the result of these operations (call it `ss`)

The "Output" in the challenge description is `s` and `ss` hexlified and concatenated.

### Solution

First we have to invert the functions. This is easy, because most of them are their own inverses (e.g. XOR), and the remaining ones are also invertable (e.g. the inverse of addition is substraction; the inverse of rotate left is rotate right; finding the inverse of a permutation is also easy).

There are 14 functions; I will not describe them one-by-one, but you can find it in the binary (they have symbols, `func1` to `func14`).

We have two slightly different ways to solve the challenge:

- Using both `s` and `ss`, we can use brute force to find the permutation of operations that will bring `ss` into `s`; based on this, we can find the order of the first group of operations (which transformed the flag to `s`). Now we can transform back `s` into the flag.

- Knowing the flag format, we can find a permutation that will bring `s` into something that starts with `ptm{` via brute force.

I chose the second approach.

We have `14` functions, hence we have `14!=87178291200` possible orders. That is a pretty big number, but my computer went through it in a couple of hours, without even bothering with parallelizing it.

### Solver program

You can find the full cargo project [here](parallel_the_mole_solution.tar.zst). Run `cargo run --release` to solve the challenge (takes 3-4 hours) or `cargo test` to check the solution.

```rust
use itertools::Itertools;

const FAKE_FLAG: &str = "{reverse_fake_flag}ptm";

fn func1(s: &mut [u8]) {
    for i in 0..4 {
        s.swap(4 * i + 1, 4 * i);
        s.swap(4 * i, 4 * i + 3);
    }
}

fn func2(s: &mut [u8]) {
    for i in 0..8 {
        s[i] ^= s[0xf - i];
    }
}

fn func3(s: &mut [u8]) {
    for (i, c) in s.iter_mut().enumerate() {
        let shift = i & 7;
        *c = (c.wrapping_shr(shift as u32)) | (c.wrapping_shl(8 - shift as u32));
    }
}

fn func4(s: &mut [u8]) {
    for i in 0..8 {
        s[0xf - i] ^= s[i];
    }
}

fn func5(s: &mut [u8]) {
    s.iter_mut()
        .zip(FAKE_FLAG.as_bytes())
        .for_each(|(c, flag_c)| {
            *c ^= flag_c;
        });
}

fn func6(s: &mut [u8]) {
    s.iter_mut().for_each(|c| {
        *c ^= 0xff;
    });
}

fn func7(s: &mut [u8]) {
    s.iter_mut().for_each(|c| {
        let mut x = *c;
        for _ in 0..7 {
            x = x.wrapping_shr(1);
            *c = c.wrapping_shl(1);
            *c |= x & 1;
        }
    });
}

fn func8(s: &mut [u8]) {
    for i in 0..8 {
        s.swap(i, 0xf - i);
    }
}

fn func9(s: &mut [u8]) {
    s.iter_mut().for_each(|c| {
        *c = c.wrapping_sub(42);
    });
}

fn func10(s: &mut [u8]) {
    s.iter_mut().for_each(|c| {
        *c = c.wrapping_shl(4) | c.wrapping_shr(4);
    });
}

fn func11(s: &mut [u8]) {
    s.iter_mut().for_each(|c| {
        *c = *c & 0x80
            | c.wrapping_shl(3) & 0x40
            | c.wrapping_shr(1) & 0x20
            | c.wrapping_shl(2) & 0x10
            | c.wrapping_shr(2) & 0x08
            | c.wrapping_shl(1) & 0x04
            | c.wrapping_shr(3) & 0x02
            | *c & 0x01;
    });
}

fn func12(s: &mut [u8]) {
    s.iter_mut().enumerate().for_each(|(i, c)| {
        *c ^= 0xff ^ i as u8;
    });
}

fn func13(s: &mut [u8]) {
    s.iter_mut().enumerate().for_each(|(i, c)| {
        *c = c.wrapping_sub(i as u8);
    });
}

fn func14(s: &mut [u8]) {
    s.iter_mut().for_each(|c| match c {
        0x61..=0x7a => *c -= 0x20,
        0x41..=0x5a => *c += 0x20,
        _ => (),
    });
}

const OPERATIONS: [fn(&mut [u8]); 14] = [
    func1, func2, func3, func4, func5, func6, func7, func8, func9, func10, func11, func12, func13,
    func14,
];

fn main() {
    let enc_flag = hex::decode("2aad2e5a49fb2d9adb908dd00eb48c8a").unwrap();

    for (i, p) in (0..14_usize).permutations(14).enumerate() {
        let mut s = enc_flag.clone();
        p.iter().for_each(|&i| {
            OPERATIONS[i](&mut s);
        });
        // ptm{
        if s.starts_with(&[0x70_u8, 0x74, 0x6d, 0x7b][..]) {
            println!("Found good permutation: {:?}", p);
            println!("FLAG bytes: {:x?}", s);
            println!("FLAG: {}", String::from_utf8(s).unwrap());
            break;
        }
        if i & 0xfffff == 0 {
            println!("i = {:#x}", i);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::OPERATIONS;
    #[test]
    fn test_solution() {
        let mut enc_flag = hex::decode("2aad2e5a49fb2d9adb908dd00eb48c8a").unwrap();
        let permutation: [usize; 14] = [7, 8, 13, 3, 9, 11, 6, 2, 4, 12, 0, 5, 1, 10];
        permutation.iter().for_each(|&i| {
            OPERATIONS[i](&mut enc_flag);
        });
        let flag = String::from_utf8(enc_flag).unwrap();
        assert_eq!(flag, String::from("ptm{brut3_f0rc3}"));
    }
}
```

The flag is `ptm{brut3_f0rc3}`.

### Files

- [parallel_the_mole_solution.tar.zst](parallel_the_mole_solution.tar.zst)