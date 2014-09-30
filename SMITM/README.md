#SMITM
---
parselog was originally written by z3ros3c and posted on [intern0t.org](https://forum.intern0t.org/offensive-guides-information/2769-stealing-credentials-via-mitm-attacks-arpspoof-sslstrip-iptables.html)

I modified the source code to accept system arguments.

excerpt from original parselog

```
:::python

try:
  lines = open('sslstrip.log','r').readlines()
except:
  lines = []
```

excerpt from modified parselog
```
:::python

for p in sys.argv[1:]:
    try:
        lines = open(p,'r').readlines()
    except:
        lines = []
```

Although it might not seem that important, but it does make a difference when executing the script.

The original parselog assumes the output from sslstrip to be sslstrip.log. Whereas the modified needs the user's input.

Example of modified parselog:
```
:::bash

parselog path/to/any/sslstrip/output
```

The modified parselog is useful when used with SMITM(Silent MITM).

SMITM saves the log from sslstrip using the following format:

```
:::bash

$(date '+%Y-%m-%d-%H-%M-%S')
```
In layman terms:
```
:::bash

Year-Month-Day-Hour-Minute-Second
```
Please Note:

The default path of the log is:
```
:::bash

/home/$(whoami)/
```
---
Issues with SMITM-stop

SMITM is derived from YAMAS and uses the same order of execution with the exception of it being silent(Once everything is set, the command-prompt will close). I wrote SMITM for embedded-linux(Rpi-odroid).

Silent does not refer to a clever way of beguiling the target, rather an output-free environment for the user.

SMITM-Stop kills sslstrip, ettercap, and clears the ip-tables. I am reluctant to advocated the use of killall as the script stopper, seeing as how it may cause unwanted system failures.
- - -

Hopefully, I will include a cleaner stop script in the next release.

Cheers,
