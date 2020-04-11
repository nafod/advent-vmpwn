full writeup: https://nafod.net/blog/2020/02/29/zdi-19-421-uhci.html

this is confusing, but the exploit flow starts in 'full.sh'

first, we kill some vmware processes to slow down heap churn.

then, the kernel module in this dir is responsible for leaking
a vmx addr, which the python script reads.

finally, we go into pwn2 and compile that kernel module to
exploit, given the leaked address we got
