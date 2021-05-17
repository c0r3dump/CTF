# m0leCon 2021 CTF Teaser - babysign

## Challenge

It's just a warmup, don't take it too seriously.

`nc challs.m0lecon.it 7012`

[server.py](server.py)

### Metadata

- Tags: `crypto`, `warmup`
- Author: *mr96*
- Points: 88
- Solves: 71

## Solution

Get `N`,`e` using `4)` then using `2)` send a character 64 times to make sure the `sha256` used to `xor` is just `sha256(32 times the character)`.

The output of our [solver script](solve.py) is the following:

```bash
> python solve.py 
[+] Opening connection to challs.m0lecon.it on port 7012: Done
b'Give me a string starting with rzrKBOwmVN such that its sha256sum ends in 5b08e.\n'
b'rzrKBOwmVN' 5b08e
bytearray(b'rzrKBOwmVNaaaaaaaa')
0
b'\n'
b'1. Sign\n'
b'2. Sign but better\n'
b'3. Verify\n'
b'4. See key\n'
b'0. Exit\n'
23798723884771524673364052676228160795552294751474471695809479184429300772029803150079484015431931959699847718466343046883109337724536177015686971055266837986255458863802420663102703950230323333834600260677252743323567031155886000114894952620222978537879037035685477909009347085071613889594295300136707512293919093374915023638080617376741349062058211457999819359898888752484166607676089064285150711602700496756342646163191199886696470855358142338829202742511034378114510235266467270295652970727163244988700665134508404595020426478999450249112734658673751791739864262269947113347745864168017848069400103566135213980469 65537
b'\n'
b'1. Sign\n'
b'2. Sign but better\n'
b'3. Verify\n'
b'4. See key\n'
b'0. Exit\n'
b'ptm{n07_3v3n_4_ch4ll3n63}1111111'
```

The flag is `ptm{n07_3v3n_4_ch4ll3n63}`.

### Files

- [solve.py](solve.py)