# SpamAndFlags 2020 - Git the Flag

## Challenge

We have found a router with an exposed [admin login screen](http://35.234.131.107/). Do you think you can obtain anything interesting?

97 points

## Solution

Right below the login form, the page informs us that the router is serving its "login code" as a git repository.
While the given `git-clone` command points to a private IPv4 address,
attempting to clone the repository over the public address of the admin page with the given credentials (`git:open source is great`) works,
and provides us with not just the code but the login credentials as well (in `config.ini`).

The password was hashed, but it was unsalted MD5 so it was not particularly hard to figure out the credentials were `admin:admin`.

Reading the source code and configuration reveals that only
loopback (`127.0.0.0/24`) and private (`192.168.0.0/16`) addresses are allowed to access the web interface.

We have found no way around the filter, but there is a way to make our requests originate from the loopback address.

SSH allows one to set up a tunnel and forward local/remote ports to the other endpoint of the connection:

```
ssh git@35.234.131.107 -p 22222 -L 127.0.0.1:8080:127.0.0.1:80 -N
```

In the above command, `-N` is used to avoid running anything on the remote server, and `-L ` is used to make the remote port `127.0.0.1:80` available on our own loopback interface as port `8080`.

Visiting `http://127.0.0.1:8080` and logging in with the already known credentials yields us the following message:

```
I was lazy to make a fake setup screen, so here's your flag: SaF{lmgtfy:"how to serve git over ssh"}
```

## Other write-ups

- <https://ctftime.org/task/11522>
