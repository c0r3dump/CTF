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