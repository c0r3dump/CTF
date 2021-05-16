# Waffle

## Description

```

We needed to upgrade this app but no one here can code in Go. Easy fix: just put a custom waf in front of it.

Author: Xato
```

The challenge offered a downloadable archive containing the source code of both the application and the WAF.

## Solution

The site was a simple site, to interact with it we needed a token, however to get this token we need to somehow bypass the WAF. After that we have an obvious SQL injection in the source code of the application.

Our first idea was HTTP smuggling, however we noticed that the WAF creates new requests instead of proxying the request to the server, therefore we dropped this idea. Our idea was to find an error in the python code and access the `/gettoken` endpoint that way.

We was thinking about two alternatives:

- Craft a normal request and modify the `promocode` in a way, that if won't be `==` to `FREEWAF` in python, but it will be in case of Go.
- Craft a request, where the parameters are somehow encoded in the path therefore the `else` branch will forward it to application where it gets extracted.

```python
    if('gettoken' in unquote(path)):
        promo = request.args.get('promocode')
        creditcard = request.args.get('creditcard')

        if promo == 'FREEWAF':
            res = jsonify({'err':'Sorry, this promo has expired'})
            res.status_code = 400
            return res

        r = requests.get(appHost+path, params={'promocode':promo,'creditcard':creditcard})

    else:
        r = requests.get(appHost+path)
```

After a lot of fuzzing and time, we gave up on the first alternative and one of us found an issue in the github page of Go [https://github.com/golang/go/issues/25192](https://github.com/golang/go/issues/25192).

After many trials we were able to get the token with the following request.

![token](token.png)

With the token the next step was to exploit the SQL injection in the database. We found out quite easily if there are two `name` parameters in the JSON, the WAF will use the second meanwhile the application will use the first. This way the SQL injection mitigations of the WAF can be bypassed.

We dumped the entire table with a simple `OR 1` query shown on the picture.

![dump](sqli.png)

Since we knew the application uses SQLite the next step was to union query, this with the data from `sqlite_master`. This way we learned that there is a table with name of `flag`.

![table](table.png)

We made a quick guess that if the table name is `flag` then the column name may be the same, therefore we issued the following request, and as it turned out it gave us the flag.

![flag](flag.png)

Flag: `ptm{n3ver_ev3r_tru5t_4_pars3r!}`