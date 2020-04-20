#!/usr/bin/env python3

from util import *
from difflib import unified_diff

if len(sys.argv) != 4:
    print("[!] %s func vmlinux1 vmlinux2" % sys.argv[0])
    exit(1)

(func, vm1, vm2) = sys.argv[1:]

funcs1 = load_funcs(vm1)
funcs2 = load_funcs(vm2)

assert func in funcs1

for l in unified_diff(normalize2(funcs1[func]),
                      normalize2(funcs2[func]),
                      fromfile=vm1, tofile=vm2):
    print(l)



