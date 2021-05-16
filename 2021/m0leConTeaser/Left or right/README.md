# m0leCon 2021 CTF Teaser - Left or right?

## Challenge

Just follow your instinct. Are you going left or right?

`nc challs.m0lecon.it 5886`

### Metadata

- Tags: `misc`
- Authors: *Drago_1729*, *matpro*, *mr96*
- Points: 217
- Solves: 19

## Solution

For every line in the parsed challenge data I 'interpreted' the string to get the relative distance from the starting point and the leftmost point during execution:

```python
def Distance(e):
    dist = 0
    leftmost = 0
    for char in e:
        if(char == 'L'):
            dist += 1
        else:
            dist -= 1
        leftmost = max(leftmost, dist)
    return (dist, leftmost)
```

```python
ret = [Distance(e) for e in chall]
```

Values on the left are positive and on the right negative.

Then I created a custom sorting algorithm that focuses on creating the smallest possible `leftmost` number when all of the strings are interpreted from the first to the last:

```python
def CustomSort(e):
    if(e[0] < 0):
        return e[1]
    else:
        return 1000000 - (e[1] - e[0])
```

```python
ret.sort(key = CustomSort)
```

I mostly discovered this using trial-and-error.

Afterwards I used the sorted list to calculate the absolute leftmost value, which is what the challenge was asking for:

```python
dst = lft = 0
start = True
for val in ret:
	if(not start):
		lft = max(lft, dst + val[1])
	else:
		lft = max(lft, val[1])
		start = False
	dst = dst + val[0]
total = str(lft)
```

```python
p.sendline(total)
```

After some loops the server returns the flag.

The final script:

```python
from pwn import remote
from hashlib import sha256

def solvepow(p, n):
    s = p.recvline()
    starting = s.split(b'with ')[1][:10].decode()
    s1 = s.split(b'in ')[-1][:n]
    i = 0
    print("Solving PoW...")
    while True:
        if sha256((starting+str(i)).encode('ascii')).hexdigest()[-n:] == s1.decode():
            print("Solved!")
            p.sendline(starting + str(i))
            break
        i += 1

##########################################################################################
##########################################################################################

def Distance(e):
    dist = 0
    leftmost = 0
    for char in e:
        if(char == 'L'):
            dist += 1
        else:
            dist -= 1
        leftmost = max(leftmost, dist)
    return (dist, leftmost)

def CustomSort(e):
    if(e[0] < 0):
        return e[1]
    else:
        return 1000000 - (e[1] - e[0])

def exploit(p):
    print(p.recvuntil("test.\n"))
    p.sendline()

    while(True):
        temp = p.recvline().decode('utf-8')
        try:
            n = int(temp)
        except:
            print(temp) # Flag found
            exit()

        #print(n)
        chall = []
        for i in range(n):
            chall.append(p.recvline().decode('utf-8')[:-1])
        #print(chall)

        ret = [Distance(e) for e in chall]
        #print(ret)

        ret.sort(key = CustomSort)
        #print(ret)

        dst = lft = 0
        start = True
        for val in ret:
            if(not start):
                lft = max(lft, dst + val[1])
            else:
                lft = max(lft, val[1])
                start = False
            dst = dst + val[0]
            #print(dst, lft)
            
        total = str(lft)

        #print('sending ' + total)
        p.sendline(total)
        print(p.recvline())

##########################################################################################
##########################################################################################

if __name__ == '__main__':
    p = remote('challs.m0lecon.it', 5886)
    solvepow(p, n = 5)
    exploit(p)
```

If we run the script, we get the flag:

```bash
python solve.py 
[+] Opening connection to challs.m0lecon.it on port 5886: Done
Solving PoW...
Solved!
b"Hello hacker! This challenge will test your programming skills.\nI will give you some strings made up only by L and R. You start at a point O, L means moving to the left by 1 unit, R means moving to the right by 1 unit.\nYour objective is to concatenate ALL these strings such that the leftmost point that you reach during your path is as near as possible to O.\nLet's call this point P. What is the distance between O and P?\n\nThe first line of the input contains a number N.\nThe following N lines contain a string made up only of the characters L and R.\nYour answer should be a non-negative integer.\nIn every testcase 0<N<=150 and the sum of the lengths of the given strings is at most 100000.\nYou must answer to 200 testcases to get the flag! Time limit is one second for each test.\n"
b'Yay\n'
...
b'Yay\n'
b'ptm{45_r16h7_45_p0551bl3}'
```

The flag is `ptm{45_r16h7_45_p0551bl3}`.

### Files

- [solve.py](solve.py)